#!/usr/bin/python3
"""Convert BIND's rolled dnstap files into ECS-shaped NDJSON for Elastic Agent.

named writes dnstap (full DNS messages, answers included) as binary Frame
Streams. This rolls the live capture with "rndc dnstap -roll", then decodes
every rolled file it hasn't seen before and appends one JSON object per DNS
message to an NDJSON file that Elastic Agent tails with its ndjson parser.

Standard library only and Python 3.6-compatible, so it runs under RHEL 8's
/usr/libexec/platform-python as well as python3 on RHEL 9+. Deployed and
scheduled by the bind_dns role (tasks/dnstap_export.yml); not meant to be
edited on the host.

Delivery is at-least-once: a crash between writing a file's events and
recording that file in the state file re-emits its events on the next run.

BIND stamps each dnstap message with one time only (query_time on queries,
response_time on responses), so an answer's latency (event.duration) comes
from pairing it with its query: same side (client-facing, resolver or
forwarder), client address and port, transport, DNS ID and question. That
needs the queries captured as well ("client query", or "auth query" for
queries named answers from its own zones). Queries still waiting for their
answer carry over to the next run in the state file, since the two can land
in different rolled files.
"""

import argparse
import base64
import collections
import datetime
import ipaddress
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

UTC = datetime.timezone.utc

# --------------------------------------------------------------------------
# Frame Streams (https://github.com/farsightsec/fstrm) file framing
# --------------------------------------------------------------------------
FSTRM_CONTROL_START = 2
FSTRM_CONTROL_STOP = 3
FSTRM_FIELD_CONTENT_TYPE = 1
DNSTAP_CONTENT_TYPE = b"protobuf:dnstap.Dnstap"
MAX_FRAME = 16 * 1024 * 1024


class Truncated(Exception):
    pass


def read_frames(f):
    """Yield each data frame's payload from a Frame Streams file."""
    def read_exact(n):
        data = f.read(n)
        if len(data) != n:
            raise Truncated("file ends mid-frame")
        return data

    while True:
        header = f.read(4)
        if not header:
            return
        if len(header) != 4:
            raise Truncated("file ends mid-frame")
        (length,) = struct.unpack("!I", header)
        if length == 0:
            # Escape sequence: a control frame follows.
            (clen,) = struct.unpack("!I", read_exact(4))
            if clen < 4 or clen > MAX_FRAME:
                raise ValueError("bad control frame length %d" % clen)
            control = read_exact(clen)
            (ctype,) = struct.unpack_from("!I", control, 0)
            if ctype == FSTRM_CONTROL_STOP:
                return
            if ctype == FSTRM_CONTROL_START:
                pos = 4
                while pos + 8 <= len(control):
                    ftype, flen = struct.unpack_from("!II", control, pos)
                    pos += 8
                    value = control[pos:pos + flen]
                    pos += flen
                    if ftype == FSTRM_FIELD_CONTENT_TYPE and value != DNSTAP_CONTENT_TYPE:
                        raise ValueError("not a dnstap stream (content type %r)" % value)
            continue
        if length > MAX_FRAME:
            raise ValueError("frame length %d exceeds sanity limit" % length)
        yield read_exact(length)


# --------------------------------------------------------------------------
# Protobuf wire format — just enough to decode dnstap.proto's two messages
# --------------------------------------------------------------------------
def read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift >= 70:
            raise ValueError("varint too long")


def pb_fields(buf):
    """Decode a protobuf message into {field_number: value}. Every field
    dnstap.proto defines is singular, so the last occurrence wins."""
    fields = {}
    pos = 0
    while pos < len(buf):
        key, pos = read_varint(buf, pos)
        number, wire_type = key >> 3, key & 7
        if wire_type == 0:
            value, pos = read_varint(buf, pos)
        elif wire_type == 1:
            (value,) = struct.unpack_from("<Q", buf, pos)
            pos += 8
        elif wire_type == 2:
            length, pos = read_varint(buf, pos)
            value = buf[pos:pos + length]
            if len(value) != length:
                raise ValueError("truncated length-delimited field")
            pos += length
        elif wire_type == 5:
            (value,) = struct.unpack_from("<I", buf, pos)
            pos += 4
        else:
            raise ValueError("unsupported protobuf wire type %d" % wire_type)
        fields[number] = value
    return fields


MESSAGE_TYPES = {
    1: "AUTH_QUERY", 2: "AUTH_RESPONSE",
    3: "RESOLVER_QUERY", 4: "RESOLVER_RESPONSE",
    5: "CLIENT_QUERY", 6: "CLIENT_RESPONSE",
    7: "FORWARDER_QUERY", 8: "FORWARDER_RESPONSE",
    9: "STUB_QUERY", 10: "STUB_RESPONSE",
    11: "TOOL_QUERY", 12: "TOOL_RESPONSE",
    13: "UPDATE_QUERY", 14: "UPDATE_RESPONSE",
}
SOCKET_PROTOCOLS = {
    1: "UDP", 2: "TCP", 3: "DOT", 4: "DOH",
    5: "DNSCryptUDP", 6: "DNSCryptTCP", 7: "DOQ",
}
# ECS network.transport for each dnstap socket protocol.
TRANSPORTS = {1: "udp", 2: "tcp", 3: "tcp", 4: "tcp", 5: "udp", 6: "tcp", 7: "udp"}

# --------------------------------------------------------------------------
# DNS wire format
# --------------------------------------------------------------------------
RR_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 39: "DNAME", 41: "OPT",
    43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3",
    51: "NSEC3PARAM", 52: "TLSA", 64: "SVCB", 65: "HTTPS", 99: "SPF",
    251: "IXFR", 252: "AXFR", 255: "ANY", 257: "CAA",
}
RR_CLASSES = {1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}
OPCODES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}
RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
    5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
    10: "NOTZONE", 16: "BADVERS", 23: "BADCOOKIE",
}
# Header flag bits, in the order dig prints them. ECS dns.header_flags.
HEADER_FLAGS = [
    (0x0400, "AA"), (0x0200, "TC"), (0x0100, "RD"),
    (0x0080, "RA"), (0x0020, "AD"), (0x0010, "CD"),
]
NAME_SPECIALS = b'.\\"();@$'


def type_name(t):
    return RR_TYPES.get(t, "TYPE%d" % t)


def class_name(c):
    return RR_CLASSES.get(c, "CLASS%d" % c)


def escape_label(label):
    out = []
    for b in label:
        if b in NAME_SPECIALS:
            out.append("\\" + chr(b))
        elif 0x21 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append("\\%03d" % b)
    return "".join(out)


def read_name(msg, pos):
    """Return (name, position after the name). Names come back without the
    trailing dot (ECS convention); the root is ".". """
    labels = []
    end = None
    hops = 0
    while True:
        if pos >= len(msg):
            raise ValueError("name runs past end of message")
        length = msg[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise ValueError("truncated compression pointer")
            if end is None:
                end = pos + 2
            hops += 1
            if hops > 127:
                raise ValueError("compression pointer loop")
            pos = ((length & 0x3F) << 8) | msg[pos + 1]
            continue
        if length & 0xC0:
            raise ValueError("unsupported label type")
        pos += 1
        if length == 0:
            break
        label = msg[pos:pos + length]
        if len(label) != length:
            raise ValueError("label runs past end of message")
        labels.append(escape_label(label))
        pos += length
    if end is None:
        end = pos
    return (".".join(labels) if labels else "."), end


def char_string(data):
    out = ['"']
    for b in data:
        if b in (0x22, 0x5C):
            out.append("\\" + chr(b))
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append("\\%03d" % b)
    out.append('"')
    return "".join(out)


def type_bitmap(data):
    types = []
    pos = 0
    while pos + 2 <= len(data):
        window, length = data[pos], data[pos + 1]
        bitmap = data[pos + 2:pos + 2 + length]
        pos += 2 + length
        for i, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    types.append(type_name(window * 256 + i * 8 + bit))
    return types


def sig_time(t):
    return datetime.datetime.fromtimestamp(t, UTC).strftime("%Y%m%d%H%M%S")


def rdata_text(msg, rtype, start, length):
    """Presentation format of one RR's rdata, as dig would print it.
    Unhandled types fall back to RFC 3597 generic syntax."""
    rdata = msg[start:start + length]
    try:
        if rtype == 1 and length == 4:
            return str(ipaddress.IPv4Address(rdata))
        if rtype == 28 and length == 16:
            return str(ipaddress.IPv6Address(rdata))
        if rtype in (2, 5, 12, 39):
            return read_name(msg, start)[0]
        if rtype == 15:
            (pref,) = struct.unpack_from("!H", rdata, 0)
            return "%d %s" % (pref, read_name(msg, start + 2)[0])
        if rtype == 6:
            mname, pos = read_name(msg, start)
            rname, pos = read_name(msg, pos)
            nums = struct.unpack_from("!IIIII", msg, pos)
            return "%s %s %d %d %d %d %d" % ((mname, rname) + nums)
        if rtype in (16, 99):
            parts = []
            pos = 0
            while pos < length:
                slen = rdata[pos]
                parts.append(char_string(rdata[pos + 1:pos + 1 + slen]))
                pos += 1 + slen
            return " ".join(parts)
        if rtype == 33:
            prio, weight, port = struct.unpack_from("!HHH", rdata, 0)
            return "%d %d %d %s" % (prio, weight, port, read_name(msg, start + 6)[0])
        if rtype == 257:
            flags, tlen = rdata[0], rdata[1]
            tag = rdata[2:2 + tlen].decode("ascii", "replace")
            return "%d %s %s" % (flags, tag, char_string(rdata[2 + tlen:]))
        if rtype == 43:
            keytag, alg, dtype = struct.unpack_from("!HBB", rdata, 0)
            return "%d %d %d %s" % (keytag, alg, dtype, rdata[4:].hex().upper())
        if rtype == 48:
            flags, proto, alg = struct.unpack_from("!HBB", rdata, 0)
            return "%d %d %d %s" % (flags, proto, alg, base64.b64encode(rdata[4:]).decode())
        if rtype == 46:
            covered, alg, labels, ottl, exp, inc, keytag = struct.unpack_from("!HBBIIIH", rdata, 0)
            signer, pos = read_name(msg, start + 18)
            sig = msg[pos:start + length]
            return "%s %d %d %d %s %s %d %s %s" % (
                type_name(covered), alg, labels, ottl, sig_time(exp), sig_time(inc),
                keytag, signer, base64.b64encode(sig).decode())
        if rtype == 47:
            nxt, pos = read_name(msg, start)
            return " ".join([nxt] + type_bitmap(msg[pos:start + length]))
    except (ValueError, IndexError, struct.error):
        pass
    if length == 0:
        return "\\# 0"
    return "\\# %d %s" % (length, rdata.hex().upper())


def parse_dns(msg):
    """Decode a DNS message. Returns a dict; on malformed input it carries
    whatever parsed cleanly plus "error"."""
    out = {"question": [], "answer": [], "authority": [], "additional": []}
    try:
        msg_id, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", msg, 0)
    except struct.error:
        out["error"] = "message shorter than a DNS header"
        return out
    out["id"] = msg_id
    out["qr"] = bool(flags & 0x8000)
    out["opcode"] = OPCODES.get((flags >> 11) & 0xF, str((flags >> 11) & 0xF))
    out["flags"] = [name for bit, name in HEADER_FLAGS if flags & bit]
    rcode = flags & 0xF
    pos = 12
    try:
        for _ in range(qd):
            name, pos = read_name(msg, pos)
            qtype, qclass = struct.unpack_from("!HH", msg, pos)
            pos += 4
            out["question"].append({"name": name, "type": type_name(qtype), "class": class_name(qclass)})
        for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
            for _ in range(count):
                name, pos = read_name(msg, pos)
                rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", msg, pos)
                pos += 10
                if pos + rdlen > len(msg):
                    raise ValueError("rdata runs past end of message")
                if rtype == 41:
                    # EDNS OPT pseudo-RR: class is the UDP payload size and
                    # TTL carries extended-rcode / version / DO bit.
                    rcode |= (ttl >> 24) << 4
                    out["edns"] = {"version": (ttl >> 16) & 0xFF, "udp_size": rclass}
                    if ttl & 0x8000:
                        out["flags"].append("DO")
                else:
                    out[section].append({
                        "name": name,
                        "type": type_name(rtype),
                        "class": class_name(rclass),
                        "ttl": ttl,
                        "data": rdata_text(msg, rtype, pos, rdlen),
                    })
                pos += rdlen
    except (ValueError, IndexError, struct.error) as exc:
        out["error"] = str(exc)
    out["rcode"] = RCODES.get(rcode, str(rcode))
    return out


# --------------------------------------------------------------------------
# dnstap frame -> ECS event
# --------------------------------------------------------------------------
def to_iso(sec, nsec):
    dt = datetime.datetime.fromtimestamp(sec, UTC).replace(microsecond=(nsec or 0) // 1000)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ip_str(raw):
    try:
        return str(ipaddress.ip_address(bytes(raw)))
    except ValueError:
        return None


def decode(raw):
    return bytes(raw).decode("utf-8", "replace")


def build_event(frame):
    """Return (event, time in ns, pairing key) for one dnstap frame, or None
    for a frame that isn't a dnstap message. The key is None when the
    message can't be paired (no parseable DNS header or question)."""
    top = pb_fields(frame)
    if top.get(15) != 1 or 14 not in top:
        return None
    m = pb_fields(top[14])
    mtype = MESSAGE_TYPES.get(m.get(1), "UNKNOWN_%s" % m.get(1))
    is_response = mtype.endswith("_RESPONSE")

    wire = m.get(14) if is_response else m.get(10)
    if wire is None:
        wire = m.get(10) if is_response else m.get(14)

    time_ns = None
    if is_response and 12 in m:
        ts = to_iso(m[12], m.get(13))
        time_ns = m[12] * 1000000000 + m.get(13, 0)
    elif 8 in m:
        ts = to_iso(m[8], m.get(9))
        time_ns = m[8] * 1000000000 + m.get(9, 0)
    else:
        ts = datetime.datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    event = {"@timestamp": ts}
    ev = {"kind": "event", "category": ["network"], "type": ["protocol"]}
    if is_response and 8 in m and 12 in m:
        duration = (m[12] - m[8]) * 1000000000 + (m.get(13, 0) - m.get(9, 0))
        if duration >= 0:
            ev["duration"] = duration
    event["event"] = ev

    network = {"protocol": "dns"}
    if m.get(3) in TRANSPORTS:
        network["transport"] = TRANSPORTS[m[3]]
    if m.get(2) in (1, 2):
        network["type"] = "ipv4" if m[2] == 1 else "ipv6"
    event["network"] = network

    # query_address is whoever sent the query (the client for CLIENT_*,
    # named itself for RESOLVER_*/FORWARDER_*); response_address answered it.
    for ecs_from, ecs_to, addr_field, port_field in (
            ("client", "source", 4, 6), ("server", "destination", 5, 7)):
        endpoint = {}
        ip = ip_str(m[addr_field]) if addr_field in m else None
        if ip:
            endpoint["ip"] = ip
        if port_field in m:
            endpoint["port"] = m[port_field]
        if endpoint:
            event[ecs_from] = endpoint
            event[ecs_to] = dict(endpoint)

    dns = {"type": "answer" if is_response else "query"}
    bind = {"message_type": mtype}
    if m.get(3) in SOCKET_PROTOCOLS:
        bind["socket_protocol"] = SOCKET_PROTOCOLS[m[3]]
    if 11 in m:
        try:
            bind["query_zone"] = read_name(bytes(m[11]), 0)[0]
        except ValueError:
            pass

    if wire is not None:
        # Bytes of the DNS message itself (what UDP carries; TCP adds a
        # 2-byte length): for amplification, truncation and tunnelling.
        bind["message_size"] = len(wire)
        parsed = parse_dns(bytes(wire))
        if "id" in parsed:
            dns["id"] = parsed["id"]
            dns["op_code"] = parsed["opcode"]
            dns["header_flags"] = parsed["flags"]
            if parsed["qr"]:
                dns["response_code"] = parsed["rcode"]
        if parsed["question"]:
            dns["question"] = parsed["question"][0]
        if parsed["answer"]:
            dns["answers"] = parsed["answer"]
            resolved = [a["data"] for a in parsed["answer"] if a["type"] in ("A", "AAAA")]
            if resolved:
                dns["resolved_ip"] = resolved
        if parsed["authority"]:
            bind["authorities"] = parsed["authority"]
        if parsed["additional"]:
            bind["additionals"] = parsed["additional"]
        if "edns" in parsed:
            bind["edns"] = parsed["edns"]
        if "error" in parsed:
            bind["parse_error"] = parsed["error"]
    event["dns"] = dns

    observer = {"vendor": "ISC", "product": "BIND", "type": "dns"}
    if 1 in top:
        observer["hostname"] = decode(top[1])
    if 2 in top:
        observer["version"] = decode(top[2])
    event["observer"] = observer
    event["bind"] = {"dnstap": bind}

    key = None
    question = dns.get("question")
    if "id" in dns and question and time_ns is not None:
        client = event.get("client", {})
        key = (pair_side(mtype), client.get("ip"), client.get("port"), m.get(3),
               dns["id"], question["name"].lower(), question["type"])
    return event, time_ns, key


def pair_side(mtype):
    # named logs a client's query as AUTH_QUERY when it answers from its own
    # zones with recursion off, but the reply as CLIENT_RESPONSE either way.
    prefix = mtype.split("_")[0]
    return "CLIENT" if prefix == "AUTH" else prefix


class QueryPairer(object):
    """Match responses to their queries to fill in event.duration."""

    # Longest wait worth pairing; BIND gives up on a recursive query after
    # resolver-query-timeout (10s by default), so this is generous.
    WINDOW_NS = 30 * 1000000000
    # Bound memory when queries are captured but their responses aren't.
    MAX_PENDING = 200000

    def __init__(self, saved=()):
        self.pending = collections.OrderedDict()
        for item in saved:
            try:
                key, time_ns = item
                self.pending[tuple(key)] = int(time_ns)
            except (TypeError, ValueError):
                continue
        self.latest = max(self.pending.values()) if self.pending else 0

    def add(self, event, time_ns, key):
        if key is None:
            return
        self.latest = max(self.latest, time_ns)
        if event["dns"]["type"] == "query":
            self.pending.pop(key, None)  # a retry with the same ID replaces it
            self.pending[key] = time_ns
            while len(self.pending) > self.MAX_PENDING:
                self.pending.popitem(last=False)
            return
        query_ns = self.pending.pop(key, None)
        if query_ns is None or "duration" in event["event"]:
            return
        duration = time_ns - query_ns
        if 0 <= duration <= self.WINDOW_NS:
            event["event"]["duration"] = duration

    def saved(self):
        # Keep only queries that could still be answered.
        cutoff = self.latest - self.WINDOW_NS
        return [[list(k), t] for k, t in self.pending.items() if t >= cutoff]


# --------------------------------------------------------------------------
# Files, state, rotation
# --------------------------------------------------------------------------
def parse_size(text):
    """BIND-style size ("100m", "1g", "512k", "unlimited") to bytes; 0 = no limit."""
    text = str(text).strip().lower()
    if text in ("unlimited", "default", "0"):
        return 0
    match = re.match(r"^(\d+)([kmg]?)$", text)
    if not match:
        raise argparse.ArgumentTypeError("invalid size %r" % text)
    mult = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[match.group(2)]
    return int(match.group(1)) * mult


def file_key(st):
    # Rolled files keep their inode across named's .0 -> .1 renames and are
    # never written again, so inode+size+mtime identifies one stably.
    return "%d:%d:%d" % (st.st_ino, st.st_size, st.st_mtime_ns)


def load_state(path):
    """Return (processed file keys, queries awaiting their response)."""
    try:
        with open(path) as f:
            state = json.load(f)
        return set(state.get("processed", [])), state.get("pending", [])
    except (IOError, OSError, ValueError, AttributeError):
        return set(), []


def save_state(path, processed, pairer):
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state.")
    with os.fdopen(fd, "w") as f:
        json.dump({"processed": sorted(processed), "pending": pairer.saved()}, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def rotate_output(path, backups):
    if backups <= 0:
        os.unlink(path)
        return
    for i in range(backups - 1, 0, -1):
        src = "%s.%d" % (path, i)
        if os.path.exists(src):
            os.replace(src, "%s.%d" % (path, i + 1))
    os.replace(path, path + ".1")


def rolled_files(active):
    directory = os.path.dirname(active) or "."
    pattern = re.compile(r"^%s\.\d+$" % re.escape(os.path.basename(active)))
    found = []
    for name in os.listdir(directory):
        if pattern.match(name):
            path = os.path.join(directory, name)
            try:
                found.append((os.stat(path).st_mtime_ns, path))
            except OSError:
                continue  # pruned by named between listdir and stat
    return [path for _, path in sorted(found)]


def convert_file(f, out, max_size, backups, output_path, pairer):
    """Append one NDJSON line per dnstap message in open file f.
    Returns (count, error)."""
    count = 0
    error = None
    try:
        for frame in read_frames(f):
            try:
                built = build_event(frame)
            except (ValueError, IndexError, struct.error) as exc:
                error = "skipped undecodable frame: %s" % exc
                continue
            if built is None:
                continue
            event, time_ns, key = built
            pairer.add(event, time_ns, key)
            if max_size and out[0].tell() >= max_size:
                out[0].close()
                rotate_output(output_path, backups)
                out[0] = open(output_path, "ab")
            out[0].write(json.dumps(event, separators=(",", ":")).encode("ascii") + b"\n")
            count += 1
    except (Truncated, ValueError, struct.error) as exc:
        error = str(exc)
    return count, error


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--dnstap-file", required=True, help="named's active dnstap-output file")
    p.add_argument("--output", required=True, help="NDJSON file to append to")
    p.add_argument("--state-file", required=True, help="records which rolled files are done")
    p.add_argument("--max-size", type=parse_size, default="100m", help="rotate output at this size")
    p.add_argument("--backups", type=int, default=3, help="rotated output files to keep")
    p.add_argument("--roll", type=int, metavar="VERSIONS",
                   help="run 'rndc dnstap -roll VERSIONS' first so the latest capture is converted")
    p.add_argument("--rndc", default="rndc", help="rndc binary")
    args = p.parse_args()

    if args.roll is not None:
        # On failure, still convert whatever named rolled on its own (size limit).
        try:
            result = subprocess.run([args.rndc, "dnstap", "-roll", str(args.roll)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    universal_newlines=True)
            if result.returncode != 0:
                print("rndc dnstap -roll failed: %s" % result.stdout.strip(), file=sys.stderr)
        except OSError as exc:
            print("rndc dnstap -roll failed: %s" % exc, file=sys.stderr)

    processed, pending = load_state(args.state_file)
    pairer = QueryPairer(pending)
    present = set()
    failures = 0
    total = 0

    out = [open(args.output, "ab")]
    try:
        for path in rolled_files(args.dnstap_file):
            try:
                f = open(path, "rb")
            except OSError:
                continue
            with f:
                # Identify the file by what was actually opened: named may
                # have renamed another file to this path since the listing.
                key = file_key(os.fstat(f.fileno()))
                present.add(key)
                if key in processed:
                    continue
                count, error = convert_file(f, out, args.max_size, args.backups, args.output, pairer)
            out[0].flush()
            os.fsync(out[0].fileno())
            total += count
            if error:
                failures += 1
                print("%s: %s (kept %d messages before it)" % (path, error, count), file=sys.stderr)
            processed.add(key)
            save_state(args.state_file, processed, pairer)
    finally:
        out[0].close()

    # Forget files named has since pruned, so the state file stays small.
    save_state(args.state_file, processed & present, pairer)
    print("converted %d dnstap messages" % total)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
