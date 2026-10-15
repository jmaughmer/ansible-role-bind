#!/usr/bin/env python3
"""Write synthetic dnstap Frame Streams files for the dnstap scenario's
converter test (molecule/dnstap/verify.yml):

    make_test_dnstap.py DIR

DIR/dnstap.tap      the "live" file - the converter must skip it
DIR/dnstap.tap.2    AUTH_QUERY for www.example.com A, then a truncated frame
DIR/dnstap.tap.1    CLIENT_RESPONSEs: www.example.com (CNAME chain with compression
                    + EDNS DO), answering .2's query 3.5 ms later; NXDOMAIN for
                    no.such.example AAAA
DIR/dnstap.tap.0    IPv6/TCP CLIENT_QUERY and its response 1.2 ms later (TXT with
                    quote/backslash, MX, AAAA, RRSIG); the CLIENT_QUERY for .1's
                    NXDOMAIN, logged after its response so it must stay unpaired
DIR/dnstap.tap.bak  not a rolled file - must be skipped

Like BIND, each message carries one timestamp only: query_time on queries,
response_time on responses.

Standard library only and Python 3.6-compatible (it runs on the test host,
under platform-python on EL8).
"""
import os
import struct
import sys
import time


def name(n):
    out = b''
    for l in n.strip('.').split('.'):
        out += bytes([len(l)]) + l.encode()
    return out + b'\0'


def rr(nm, t, ttl, rdata, cls=1):
    return nm + struct.pack('!HHIH', t, cls, ttl, len(rdata)) + rdata


def varint(v):
    o = b''
    while True:
        b = v & 0x7f
        v >>= 7
        if v:
            o += bytes([b | 0x80])
        else:
            return o + bytes([b])


def f_varint(n, v): return varint(n << 3 | 0) + varint(v)
def f_bytes(n, b): return varint(n << 3 | 2) + varint(len(b)) + b
def f_fixed32(n, v): return varint(n << 3 | 5) + struct.pack('<I', v)


# www.example.com A -> CNAME web.example.com (compressed) -> 2x A, NS authority, OPT with DO
q = name('www.example.com')
hdr = struct.pack('!HHHHHH', 0xbeef, 0x8000 | 0x0400 | 0x0100 | 0x0080 | 0x0020, 1, 3, 1, 1)
msg = hdr + q + struct.pack('!HH', 1, 1)
ptr_www = b'\xc0\x0c'
ptr_example = b'\xc0\x10'
ans_cname_off = len(msg)
msg += rr(ptr_www, 5, 300, b'\x03web' + ptr_example)
ptr_web = struct.pack('!H', 0xc000 | (ans_cname_off + 12))
msg += rr(ptr_web, 1, 60, bytes([192, 0, 2, 1]))
msg += rr(ptr_web, 1, 60, bytes([192, 0, 2, 2]))
msg += rr(ptr_example, 2, 3600, b'\x03ns1' + ptr_example)
msg += b'\x00' + struct.pack('!HHIH', 41, 1232, 0x00008000, 0)
resp1 = msg
query1 = struct.pack('!HHHHHH', 0xbeef, 0x0100, 1, 0, 0, 0) + q + struct.pack('!HH', 1, 1)

# NXDOMAIN for AAAA
resp2 = struct.pack('!HHHHHH', 7, 0x8000 | 0x0100 | 0x0080 | 3, 1, 0, 0, 0) + name('no.such.example') + struct.pack('!HH', 28, 1)
query2 = struct.pack('!HHHHHH', 7, 0x0100, 1, 0, 0, 0) + name('no.such.example') + struct.pack('!HH', 28, 1)

# ANY example.com: TXT (with quote/backslash), MX, AAAA, RRSIG
m = struct.pack('!HHHHHH', 8, 0x8000 | 0x0400, 1, 4, 0, 0) + name('example.com') + struct.pack('!HH', 255, 1)
m += rr(b'\xc0\x0c', 16, 30, b'\x0bv=spf1 -all' + b'\x05a"b\\c')
m += rr(b'\xc0\x0c', 15, 30, b'\x00\x0a' + b'\x04mail\xc0\x0c')
m += rr(b'\xc0\x0c', 28, 30, bytes.fromhex('20010db8000000000000000000000001'))
m += rr(b'\xc0\x0c', 46, 30, struct.pack('!HBBIIIH', 1, 13, 2, 300, 1790000000, 1780000000, 12345) + name('example.com') + b'\x01\x02\x03')
resp3 = m
query3 = struct.pack('!HHHHHH', 8, 0, 1, 0, 0, 0) + name('example.com') + struct.pack('!HH', 255, 1)


T = 1791900000 * 1000000000  # base time, ns


def dnstap(mtype, wire, t_ns, fam=1, proto=1, qa=bytes([10, 0, 0, 5]), ra=bytes([10, 0, 0, 1])):
    sec, nsec = divmod(t_ns, 1000000000)
    mm = f_varint(1, mtype) + f_varint(2, fam) + f_varint(3, proto) + f_bytes(4, qa) + f_bytes(5, ra)
    mm += f_varint(6, 51234) + f_varint(7, 53)
    if mtype % 2:  # queries are odd message types
        mm += f_varint(8, sec) + f_fixed32(9, nsec) + f_bytes(10, wire)
    else:
        mm += f_varint(12, sec) + f_fixed32(13, nsec) + f_bytes(14, wire)
    return f_bytes(1, b'ns1.test') + f_bytes(2, b'9.16.23-RH') + f_varint(15, 1) + f_bytes(14, mm)


def fstrm(frames, stop=True, ctype=b'protobuf:dnstap.Dnstap'):
    start = struct.pack('!I', 2) + struct.pack('!II', 1, len(ctype)) + ctype
    out = struct.pack('!II', 0, len(start)) + start
    for fr in frames:
        out += struct.pack('!I', len(fr)) + fr
    if stop:
        out += struct.pack('!III', 0, 4, 3)
    return out


d = sys.argv[1]
os.makedirs(d)
v6 = bytes.fromhex('20010db8000000000000000000000005')
v6s = bytes.fromhex('20010db8000000000000000000000001')
AUTH_QUERY, CLIENT_QUERY, CLIENT_RESPONSE = 1, 5, 6
tcp6 = dict(fam=2, proto=2, qa=v6, ra=v6s)
open(os.path.join(d, 'dnstap.tap'), 'wb').write(fstrm([dnstap(CLIENT_RESPONSE, resp1, T)], stop=False))  # active: must be skipped
open(os.path.join(d, 'dnstap.tap.2'), 'wb').write(
    fstrm([dnstap(AUTH_QUERY, query1, T + 100000000)], stop=False) + struct.pack('!I', 500) + b'xx')
time.sleep(0.05)
open(os.path.join(d, 'dnstap.tap.1'), 'wb').write(fstrm([
    dnstap(CLIENT_RESPONSE, resp1, T + 103500000),
    dnstap(CLIENT_RESPONSE, resp2, T + 150000000)]))
time.sleep(0.05)
open(os.path.join(d, 'dnstap.tap.0'), 'wb').write(fstrm([
    dnstap(CLIENT_QUERY, query3, T + 200000000, **tcp6),
    dnstap(CLIENT_RESPONSE, resp3, T + 201200000, **tcp6),
    dnstap(CLIENT_QUERY, query2, T + 149000000)]))
open(os.path.join(d, 'dnstap.tap.bak'), 'wb').write(b'not a rolled file')
