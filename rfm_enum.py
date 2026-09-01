#!/usr/bin/env python3
# encoding: utf-8
"""Enumerate remote function modules callable WITHOUT authentication on an AS ABAP.

An RFC type-3 connection names the function module it wants in its very first packet,
before any logon. A small set of modules -- RFC_PING, RFC_SYSTEM_INFO and a handful of
others -- is answered by the work process before the logon check runs; the rest reply
"error during logon" (kernel error 00024). This tool sends the anonymous connect for each
candidate and classifies the reply, so it reports which function modules a system exposes
to an unauthenticated caller and, for RFC_SYSTEM_INFO, prints the system details that come
back.

Built on pysap for the SAP NI transport and SAProuter traversal. No NetWeaver RFC SDK,
no SAP GUI, no credentials.

Everything lives in this one file, in three layers bottom-up:

  CPIC codec   the TLV payload that carries the function name, and the EBCDIC "error
               during logon" record that is the whole oracle
  APPC layer   the 80-byte version-6 SAP RFC frames (init / allocate / send / ...)
  client + CLI drives the handshake up to the first reply, classifies it, reports it

    NI  ->  GW_NORMAL_CLIENT
        ->  F_INITIALIZE_CONVERSATION      (gateway assigns a conversation id)
        ->  F_SET_PARTNER_LU_NAME
        ->  F_ALLOCATE                     (gateway attaches a work process)
        ->  F_SAP_SEND [CPIC connect, function=<target>, no user/password TLVs]
        <-  F_SAP_SEND [reply]

Authorized security testing only.
"""
import argparse
import json
import socket
import struct
import sys
import time

from scapy.packet import Raw

from pysap.SAPRFC import SAPRFC
from pysap.SAPRouter import SAPRoutedStreamSocket


# =============================================================================
# CPIC / RFC payload codec -- the layer that rides inside APPC F_SAP_SEND frames.
#
# The connect payload opens with a 12-byte EBCDIC eyecatcher ("RFC" + nine digits) and is
# then a chain of
#     <tag:2 BE><len:2 BE><value:len><tag:2 BE>
# where the tag is repeated as a closer. The chain ends with tag 0xffff and an 8-byte
# trailer holding the payload length. Server replies use the same chain but carry no
# eyecatcher, and once the connect is accepted the session codepage flips to 4103
# (UTF-16LE), so reply values are UTF-16LE text.
#
# Rejections are not a TLV chain at all: they are a fixed EBCDIC record beginning "FREE",
# followed by a five-digit error number and the message text. That record is the oracle
# that says whether a function module was dispatched or the kernel demanded a logon first.
# =============================================================================

#: EBCDIC(cp037) -> Latin-1 translation table.
E2A = bytes(range(256)).decode("cp037").encode("latin-1")
#: Latin-1 -> EBCDIC(cp037).
A2E = bytes(range(256)).decode("latin-1").encode("cp037", "replace")

EYECATCHER = "RFC000000000".encode("cp037")
END_TAG = 0xffff

# TLV tags observed on the wire, named after the value they carried in a real NW RFC SDK
# connect.
TAG_FLAGS1 = 0x0101       # 8 bytes of feature bits
TAG_FLAGS2 = 0x0103       # 4 bytes
TAG_FLAGS3 = 0x0106       # 11 bytes
TAG_NONCE = 0x0514        # 16 bytes, part timestamp part random
TAG_CLIENT = 0x0114       # "001"
TAG_USER = 0x0111         # "DEVELOPER"      -- absent on an anonymous connect
TAG_PASSWD = 0x0117       # 17 bytes, scrambled -- absent on an anonymous connect
TAG_LANG = 0x0115         # "E"
TAG_TRACE = 0x0501        # 1 byte
TAG_LOCAL_IP = 0x0007
TAG_LOCAL_IP6 = 0x0018
TAG_LANG2 = 0x0011
TAG_REL = 0x0012          # "793"
TAG_REL2 = 0x0013
TAG_HOSTNAME = 0x0008
TAG_OS = 0x0006           # "<unknown>"
TAG_PROGRAM = 0x0130      # "rfccall"
TAG_UNKNOWN_0502 = 0x0502
TAG_REL3 = 0x000b
TAG_FUNCTION = 0x0102     # "RFCPING"        -- the function module to dispatch

#: Order matters: the kernel parses the chain positionally in places.
CONNECT_ORDER = [TAG_FLAGS1, TAG_FLAGS2, TAG_FLAGS3, TAG_NONCE, TAG_CLIENT, TAG_USER,
                 TAG_PASSWD, TAG_LANG, TAG_TRACE, TAG_LOCAL_IP, TAG_LOCAL_IP6, TAG_LANG2,
                 TAG_REL, TAG_REL2, TAG_HOSTNAME, TAG_OS, TAG_PROGRAM, TAG_UNKNOWN_0502,
                 TAG_REL3, TAG_FUNCTION]


def to_ebcdic(s):
    return s.encode("latin-1").translate(A2E) if isinstance(s, str) else s.translate(A2E)


def from_ebcdic(b):
    return b.translate(E2A).decode("latin-1")


def tlv(tag, value):
    """One element: opener, length, value, closer."""
    if isinstance(value, str):
        value = value.encode("latin-1")
    return struct.pack("!HH", tag, len(value)) + value + struct.pack("!H", tag)


def parse_tlvs(payload):
    """Decode a chain into [(tag, value)]. Returns (elements, trailing_bytes).

    Stops at the 0xffff terminator or at the first element whose closer does not match its
    opener -- a real server reply always closes every element it opens, so a mismatch means
    we have run off the end of the chain into the trailer.
    """
    out, off = [], 0
    while off + 4 <= len(payload):
        tag, n = struct.unpack("!HH", payload[off:off + 4])
        if tag == END_TAG:
            off += 4
            break
        if off + 6 + n > len(payload):
            break
        if payload[off + 4 + n:off + 6 + n] != struct.pack("!H", tag):
            break
        out.append((tag, payload[off + 4:off + 4 + n]))
        off += 6 + n
    return out, payload[off:]


def nonce(now=None):
    """The 16-byte 0x0514 value: a hex timestamp plus per-connection jitter.

    The SDK derives it from the clock; the kernel only echoes it back, so any well-formed
    value is accepted. Generating it rather than replaying a captured one keeps concurrent
    probes from colliding on the same connection identity.
    """
    t = int(now if now is not None else time.time())
    return struct.pack("!I", t & 0xffffffff) + b"\xd1\xa9\xba\x7b" + \
        struct.pack("!I", (t * 2654435761) & 0xffffffff) + b"\x00\x05\x14\x00"[:4]


def build_connect(function, user=None, passwd=None, client="001", lang="E",
                  hostname="localhost", program="pysap", local_ip="127.0.0.1",
                  local_ip6="::1", release="793", os_name="<unknown>"):
    """Build the CPIC connect payload that carries the function module to dispatch.

    Omitting `user` and `passwd` produces the *anonymous* connect: byte for byte what the
    NetWeaver RFC SDK sends when no credentials are configured, minus tags 0x0111 and
    0x0117. Whether the kernel then dispatches `function` or answers "error during logon"
    is exactly the question this tool exists to ask.
    """
    values = {
        TAG_FLAGS1: bytes.fromhex("0301010101010000"),
        TAG_FLAGS2: bytes.fromhex("00000e0b"),
        TAG_FLAGS3: bytes.fromhex("04010003000a0200000023"),
        TAG_NONCE: nonce(),
        TAG_CLIENT: client,
        TAG_LANG: lang,
        TAG_TRACE: b"\x01",
        TAG_LOCAL_IP: local_ip,
        TAG_LOCAL_IP6: local_ip6,
        TAG_LANG2: lang,
        TAG_REL: release,
        TAG_REL2: release,
        TAG_HOSTNAME: hostname,
        TAG_OS: os_name,
        TAG_PROGRAM: program,
        TAG_UNKNOWN_0502: b"",
        TAG_REL3: release,
        TAG_FUNCTION: function,
    }
    if user is not None:
        values[TAG_USER] = user
    if passwd is not None:
        values[TAG_PASSWD] = scramble_password(passwd)

    body = b"".join(tlv(t, values[t]) for t in CONNECT_ORDER if t in values)
    # The chain is closed by an empty element carrying the terminator tag.
    body += tlv(END_TAG, b"")
    payload = EYECATCHER + body
    # Trailer: the payload length up to but excluding the trailer, then two constants the
    # kernel echoes back unchanged.
    return payload + struct.pack("!I", len(payload)) + b"\x00\x00\x85\x00"


def scramble_password(passwd):
    """Placeholder for the 0x0117 obfuscation -- deliberately not implemented.

    Enumerating unauthenticated function modules never sends a password: the whole point is
    the anonymous connect. Callers that pass `passwd` get a clear failure rather than a
    silently wrong 17-byte blob.
    """
    raise NotImplementedError(
        "0x0117 password scrambling is not implemented; this tool probes the anonymous "
        "connect path only. Use the NetWeaver RFC SDK for authenticated calls.")


def iter_until_unprintable(text):
    """Yield characters up to the first non-printable one (the pad boundary)."""
    for ch in text:
        if ch == "\t" or 0x20 <= ord(ch) < 0x7f:
            yield ch
        else:
            return


class RFCError(object):
    """A kernel-level rejection: the EBCDIC "FREE" record, not a TLV chain."""

    MAGIC = to_ebcdic("FREE")

    def __init__(self, payload):
        self.raw = payload
        self.code = from_ebcdic(payload[12:17]).strip()
        # The record is fixed-width and right-padded; keep only the leading run of
        # printable characters so trailing pad bytes do not leak into the message.
        self.message = "".join(iter_until_unprintable(from_ebcdic(payload[17:]))).rstrip()

    @classmethod
    def matches(cls, payload):
        return payload[:4] == cls.MAGIC

    def __str__(self):
        return "%s %s" % (self.code, self.message)


def decode_reply(payload):
    """Classify a server F_SAP_SEND payload.

    Returns (kind, detail) where kind is:
      "error" -- detail is an RFCError; the kernel refused before dispatching
      "data"  -- detail is [(tag, value)]; the call was dispatched and answered
    """
    if RFCError.matches(payload):
        return "error", RFCError(payload)
    tlvs, _ = parse_tlvs(payload)
    return "data", tlvs


def as_text(value):
    """Render a reply value, which may be UTF-16LE once the session is Unicode."""
    if len(value) >= 2 and value[1::2].count(0) > len(value) // 4:
        try:
            return value.decode("utf-16-le").rstrip("\x00 ")
        except UnicodeDecodeError:
            pass
    if all(0x20 <= c < 0x7f or c == 0 for c in value):
        return value.decode("latin-1").rstrip("\x00 ")
    return value.hex()


# The RFCSI_EXPORT structure returned by RFC_SYSTEM_INFO, as a flat character record.
# Field widths recovered by fitting known values (kernel release, IP, OS) against a live
# reply; the record is fixed-layout SPACE-padded character data.
RFCSI_FIELDS = [
    ("RFCPROTO", 3), ("RFCCHARTYP", 4), ("RFCINTTYP", 3), ("RFCFLOTYP", 3),
    ("RFCDEST", 32), ("RFCHOST", 8), ("RFCSYSID", 8), ("RFCDATABS", 8),
    ("RFCDBHOST", 32), ("RFCDBSYS", 10), ("RFCSAPRL", 4), ("RFCMACH", 5),
    ("RFCOPSYS", 10), ("RFCTZONE", 6), ("RFCDAYST", 1), ("RFCIPADDR", 15),
    ("RFCKERNRL", 4), ("RFCHOST2", 32), ("RFCSI_RESV", 12), ("RFCIPV6ADDR", 45),
]


def parse_rfcsi(record):
    """Split the RFC_SYSTEM_INFO character record into its named fields."""
    if not isinstance(record, str):
        record = as_text(record)
    out, off = {}, 0
    for name, width in RFCSI_FIELDS:
        out[name] = record[off:off + width].strip()
        off += width
    return out


# =============================================================================
# APPC layer -- the version-6 SAP RFC frames that ride on top of SAP NI.
#
# pysap's version-6 SAPRFC serialises to 48 bytes. Kernel 7.93's gwrd reads the version
# field only once a message is at least 80 bytes long and rejects anything shorter with
# "wrong appc header version ... (<n> bytes)" -- misleading, the version byte is fine, the
# message is simply too short. So the header is built here explicitly at 80 bytes.
#
# Header layout, recovered from a captured NW RFC SDK conversation:
#   0x00 version(6)  0x01 func_type  0x02 protocol(2)  0x04 uid(0xffff)
#   0x0a info2  0x10 info3  0x1a per-function constants
#   0x28 conversation id (8 ASCII digits, assigned by the gateway)
#   0x30 32-byte extended-init block
# The bytes at 0x0a-0x1f differ per function type; their individual meanings are not all
# established, so they are reproduced verbatim. That is enough -- the gateway is a state
# machine over the function type, not over these flags.
# =============================================================================

FUNC_INITIALIZE_CONVERSATION = 0x01
FUNC_ACCEPT_CONVERSATION = 0x03
FUNC_ALLOCATE = 0x05
FUNC_ASEND_DATA = 0x08
FUNC_ARECEIVE = 0x0a
FUNC_DEALLOCATE = 0x0b
FUNC_SET_PARTNER_LU_NAME = 0x0f
FUNC_SAP_SEND = 0xcb

HDR_LEN = 80
CONV_ID_OFF = 0x28
EXTEND_OFF = 0x30

#: Per-function header bytes outside the named fields, offset -> value. Taken verbatim.
_HDR_CONST = {
    FUNC_INITIALIZE_CONVERSATION: {0x0a: 0x01, 0x10: 0xc0, 0x15: 0x04,
                                   0x1a: 0x01, 0x1b: 0x75, 0x1e: 0x05},
    FUNC_SET_PARTNER_LU_NAME: {0x0a: 0x01, 0x1b: 0x90, 0x1e: 0x04},
    FUNC_ALLOCATE: {0x1e: 0x01},
    FUNC_SAP_SEND: {0x1b: 0x08, 0x1e: 0x05, 0x1f: 0x0c},
    FUNC_DEALLOCATE: {},
}


def _pad(s, n, fill=b"\x00"):
    b = s.encode("latin-1") if isinstance(s, str) else s
    return b[:n] + fill * max(0, n - len(b))


def appc_header(func_type, conv_id=b"", extend=None):
    """Build the 80-byte APPC header for `func_type`."""
    h = bytearray(HDR_LEN)
    h[0x00] = 0x06
    h[0x01] = func_type
    h[0x02] = 0x02
    h[0x04:0x06] = b"\xff\xff"
    for off, val in _HDR_CONST.get(func_type, {}).items():
        h[off] = val
    h[CONV_ID_OFF:CONV_ID_OFF + 8] = _pad(conv_id, 8)
    h[EXTEND_OFF:HDR_LEN] = extend if extend is not None else _pad(b"", 28) + b"\xff\xff\x00\x00"
    return bytes(h)


def extend_block(short_dest="NWRFC", lu="", tp="", ctype=0x49, client_info=0x01):
    """The 32-byte extended-init block carried by F_INITIALIZE_CONVERSATION."""
    return (_pad(short_dest, 8, b" ") + _pad(lu, 8) + _pad(tp, 8, b" ") +
            bytes([ctype, client_info]) + b"\x00\x00" + b"\x00\x00" + b"\xff\xff")


def initialize_conversation(local_ip="127.0.0.1", os_user="pysap", service="sapdp00",
                            guid=None):
    """F_INITIALIZE_CONVERSATION -- opens the CPIC conversation with the gateway.

    `guid` is 32 ASCII hex chars the SDK derives from the clock; the gateway only echoes
    it, so any distinct value works. `service` is the dispatcher service name
    (sapdp<sysnr>); the gateway normalises it to its own instance.
    """
    if guid is None:
        t = "%08X" % (int(time.time()) & 0xffffffff)
        guid = t + t + t + t
    body = bytearray(373)
    body[0x000:0x020] = _pad("NWRFC", 32, b" ")
    body[0x020:0x022] = b"\x01\x01"
    body[0x022:0x02a] = _pad("CPIC", 8)
    body[0x02a:0x04a] = _pad(guid, 32)
    body[0x04a:0x04e] = b"\x00\x00\x00\x01"
    body[0x04e:0x056] = b"\xff\xff\xff\xfe\xff\xff\xff\xfe"
    body[0x056:0x058] = b"\x02\x00"
    body[0x069:0x069 + len(local_ip)] = local_ip.encode("latin-1")
    body[0x0f9:0x0f9 + len(os_user)] = os_user.encode("latin-1")[:32]
    body[0x135:0x135 + len(service)] = service.encode("latin-1")[:32]
    ext = extend_block(lu=local_ip, tp=service)
    # No conversation exists yet, so the id slot is blank-filled rather than NUL-filled.
    return appc_header(FUNC_INITIALIZE_CONVERSATION, b" " * 8, ext) + bytes(body)


def set_partner_lu_name(conv_id, partner="127.0.0.1"):
    """F_SET_PARTNER_LU_NAME -- names the host the conversation is destined for."""
    ext = bytearray(_pad(partner[:8], 8) + b"\x00" * 24)
    ext[0x08:0x0c] = struct.pack("!I", len(partner))
    ext[0x1c:0x1e] = b"\xff\xff"
    return (appc_header(FUNC_SET_PARTNER_LU_NAME, conv_id, bytes(ext)) +
            _pad(partner, 128, b" ") + b"\x00" * 16)


def allocate(conv_id):
    """F_ALLOCATE -- asks the gateway to attach a work process to the conversation."""
    return appc_header(FUNC_ALLOCATE, conv_id)


def sap_send(conv_id, payload):
    """F_SAP_SEND -- carries a CPIC/RFC payload."""
    return appc_header(FUNC_SAP_SEND, conv_id) + payload


def deallocate(conv_id):
    """F_DEALLOCATE -- tears the conversation down politely."""
    return appc_header(FUNC_DEALLOCATE, conv_id)


def appc_parse(frame):
    """Split a received APPC frame into (func_type, conv_id, payload)."""
    if len(frame) < HDR_LEN:
        return None, b"", frame
    conv = frame[CONV_ID_OFF:CONV_ID_OFF + 8].rstrip(b"\x00 ")
    return frame[1], conv, frame[HDR_LEN:]


# =============================================================================
# Client -- drives the handshake up to the first reply and classifies it.
#
# An RFC type-3 client does not log on and then say which function it wants: the very first
# CPIC payload carries both the credentials and a function module name (tag 0x0102). The
# work process decides from that one packet whether to run the function or demand a logon
# first. Probing unauthenticated callability therefore needs no parameter serialisation and
# no session -- send the anonymous connect naming the function, read one reply, classify.
# =============================================================================

class RFCProbeError(Exception):
    """The conversation broke down before a verdict could be reached."""


class Reply(object):
    """One classified answer to a probe.

    verdict: "unauthenticated" | "logon_required" | "rejected" | "no_reply"
    code:    kernel error number (e.g. "00024") when the call was refused
    message: kernel error text, decoded from EBCDIC
    values:  [(tag, value)] of a successful reply
    raw:     the reply payload, for cases the classifier does not cover
    """

    def __init__(self, verdict, code=None, message=None, values=None, raw=b""):
        self.verdict = verdict
        self.code = code
        self.message = message
        self.values = values or []
        self.raw = raw

    @property
    def unauthenticated(self):
        return self.verdict == "unauthenticated"

    def text_values(self):
        return [(tag, as_text(v)) for tag, v in self.values]

    def to_dict(self, function=None, include_raw=True):
        """A JSON-serialisable record of this reply, for a report file."""
        d = {
            "function": function,
            "verdict": self.verdict,
            "code": self.code,
            "message": self.message,
            "values": [{"tag": "%04x" % t, "text": as_text(v)} for t, v in self.values],
        }
        if include_raw:
            d["raw"] = self.raw.hex()
        return d

    def __str__(self):
        if self.code:
            return "%s (%s %s)" % (self.verdict, self.code, self.message)
        return "%s (%d values)" % (self.verdict, len(self.values))


#: Kernel error numbers that mean "the function was never dispatched, log on first".
LOGON_ERRORS = {"00024"}


class RFCClient(object):
    """Drives one probe per connection.

    A conversation is single-use: the work process tears it down after refusing a logon, so
    each function module tested needs its own connection. That is the protocol's choice.
    """

    def __init__(self, host, port=3300, route=None, timeout=5,
                 client="001", lang="E", program="pysap", hostname=None, sysnr=None):
        self.host = host
        self.port = port
        self.route = route
        self.timeout = timeout
        self.client = client
        self.lang = lang
        self.program = program
        self.hostname = hostname or socket.gethostname()
        # Dispatcher service name to route to, derived from the port when not given
        # (3300 -> sapdp00). The gateway normalises it, so an approximate value is fine.
        self.sysnr = sysnr if sysnr is not None else "%02d" % (port - 3300) \
            if 3300 <= port <= 3399 else "00"
        self.conn = None
        self.conv_id = b""
        self.codepage = b""

    def _open(self):
        self.conn = SAPRoutedStreamSocket.get_nisocket(
            self.host, self.port, self.route, base_cls=Raw)
        self.conn.ins.settimeout(self.timeout)

    def _send(self, data):
        self.conn.send(Raw(load=bytes(data)))

    def _recv(self):
        """One NI message, or None if the peer said nothing before the timeout."""
        try:
            return bytes(self.conn.recv().payload)
        except (socket.timeout, EOFError, ConnectionResetError, struct.error):
            return None

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _local_ip(self):
        try:
            return self.conn.ins.getsockname()[0]
        except OSError:
            return "127.0.0.1"

    def _gw_normal_client(self):
        """GW_NORMAL_CLIENT: the unauthenticated front door of the gateway.

        pysap models this packet correctly; two byte-level details are fixed up here -- the
        service field carries the local IP, and the tail carries the NI protocol version.
        """
        p = SAPRFC(version=2, req_type=3, address="0.0.0.0", service=self.program,
                   codepage=b"1100", lu=self.hostname, tp=self.program,
                   conversation_id="", appc_header_version=6, accept_info=0xcb,
                   idx=-1, rc=0, echo_data=0, filler=0)
        b = bytearray(bytes(p))
        b[0x02:0x06] = socket.inet_aton(self._local_ip())
        b[0x0a:0x14] = _pad(self.program, 10)
        b[0x18:0x1e] = b"\x00\x00\x00\x00\x00\x06"
        self._send(bytes(b))
        r = self._recv()
        if r is None:
            raise RFCProbeError("gateway did not answer GW_NORMAL_CLIENT")
        self.codepage = r[0x14:0x18]
        return r

    def connect(self):
        """Run the handshake up to the point where a function module can be named."""
        self._open()
        self._gw_normal_client()

        self._send(initialize_conversation(
            local_ip=self._local_ip(), os_user=self.program,
            service="sapdp%s" % self.sysnr))
        r = self._recv()
        if r is None:
            raise RFCProbeError("gateway did not answer F_INITIALIZE_CONVERSATION")
        _, self.conv_id, _ = appc_parse(r)
        if not self.conv_id:
            raise RFCProbeError("gateway assigned no conversation id")

        self._send(set_partner_lu_name(self.conv_id, self.host))
        self._send(allocate(self.conv_id))
        r = self._recv()
        if r is None:
            raise RFCProbeError("gateway did not answer F_ALLOCATE")
        return self

    def probe(self, function):
        """Send the anonymous connect naming `function` and classify the reply."""
        payload = build_connect(
            function, client=self.client, lang=self.lang,
            hostname=self.hostname, program=self.program, local_ip=self._local_ip())
        self._send(sap_send(self.conv_id, payload))

        # The work process may answer with several frames (F_ASEND_DATA carrying the error,
        # then F_ARECEIVE and F_DEALLOCATE). The first one with a payload is the verdict.
        for _ in range(4):
            r = self._recv()
            if r is None:
                break
            _, _, body = appc_parse(r)
            if not body:
                continue
            kind, detail = decode_reply(body)
            if kind == "error":
                verdict = "logon_required" if detail.code in LOGON_ERRORS else "rejected"
                return Reply(verdict, detail.code, detail.message, raw=body)
            return Reply("unauthenticated", values=detail, raw=body)
        return Reply("no_reply")


def probe_function(host, function, port=3300, route=None, timeout=5, **kw):
    """Convenience wrapper: one connection, one function module, one verdict."""
    with RFCClient(host, port, route, timeout, **kw) as c:
        c.connect()
        return c.probe(function)


# =============================================================================
# CLI
# =============================================================================

#: Checked first when no wordlist is given: modules known or likely to answer pre-logon,
#: plus a couple of negative controls.
DEFAULT_CANDIDATES = [
    "RFC_PING", "RFC_SYSTEM_INFO", "RFCPING", "RFC_PING_AND_WAIT",
    "RFC_GET_ATTRIBUTES", "SYSTEM_RESET_RFC_SERVER", "RFC_DOCU", "RFC_METADATA_GET",
    "RFC_FUNCTION_SEARCH", "RFC_GET_FUNCTION_INTERFACE", "STFC_CONNECTION",
    "STFC_DEEP_STRUCTURE", "SYSTEM_INVISIBLE_GUI", "RFC_READ_TABLE", "TH_SAPREL",
    "SUSR_RFC_USER_INTERFACE",
]

VERDICT_MARK = {
    "unauthenticated": "\033[1;31m[UNAUTH]\033[0m",
    "logon_required": "\033[0;34m[logon ]\033[0m",
    "rejected": "\033[0;33m[reject]\033[0m",
    "no_reply": "\033[0;90m[silent]\033[0m",
}


def load_candidates(path):
    with open(path) as fh:
        return [ln.strip() for ln in fh
                if ln.strip() and not ln.lstrip().startswith("#")]


def _hms(seconds):
    seconds = int(seconds)
    if seconds >= 3600:
        return "%dh%02dm" % (seconds // 3600, (seconds % 3600) // 60)
    if seconds >= 60:
        return "%dm%02ds" % (seconds // 60, seconds % 60)
    return "%ds" % seconds


class Progress(object):
    """A single self-overwriting status line on stderr.

    Dependency-free and quiet: draws only to a real terminal, throttles to a few redraws a
    second, and clears its line whenever a result is about to print to stdout so the two
    never tangle.
    """

    def __init__(self, total, enabled=True):
        self.total = total
        self.enabled = enabled and sys.stderr.isatty()
        self.done = 0
        self.hits = 0
        self._last = 0.0
        self._start = time.time()
        self._width = 0

    def clear(self):
        if self.enabled and self._width:
            sys.stderr.write("\r" + " " * self._width + "\r")
            sys.stderr.flush()
            self._width = 0

    def advance(self, hit, force=False):
        self.done += 1
        if hit:
            self.hits += 1
        if not self.enabled:
            return
        now = time.time()
        if not force and now - self._last < 0.1:
            return
        self._last = now
        elapsed = now - self._start
        rate = self.done / elapsed if elapsed else 0
        eta = (self.total - self.done) / rate if rate else 0
        line = "  [%d/%d] %.0f%%  unauth=%d  %.0f/s  ETA %s" % (
            self.done, self.total, 100.0 * self.done / self.total,
            self.hits, rate, _hms(eta))
        self._width = max(self._width, len(line))
        sys.stderr.write("\r" + line.ljust(self._width))
        sys.stderr.flush()

    def close(self):
        self.clear()


def parse_args(argv):
    ap = argparse.ArgumentParser(
        description=__doc__.strip().splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host", help="AS ABAP host (or SAProuter target)")
    ap.add_argument("-p", "--port", type=int, default=3300,
                    help="gateway port, 33NN [%(default)d]")
    ap.add_argument("--route", help="SAProuter route string")
    ap.add_argument("-w", "--wordlist",
                    help="file of function module names, one per line "
                         "(default: a built-in candidate list)")
    ap.add_argument("-f", "--function", action="append", metavar="FM",
                    help="test one function module (repeatable)")
    ap.add_argument("-c", "--client", default="001", help="SAP client [%(default)s]")
    ap.add_argument("-l", "--lang", default="E", help="logon language [%(default)s]")
    ap.add_argument("--program", default="pysap",
                    help="TP/program name to present [%(default)s]")
    ap.add_argument("-t", "--timeout", type=float, default=5.0,
                    help="per-probe socket timeout [%(default)s]")
    ap.add_argument("-T", "--threads", type=int, default=1, metavar="N",
                    help="concurrent probes; each uses its own connection [%(default)d]")
    ap.add_argument("--all", action="store_true",
                    help="print every result, not just the unauthenticated ones")
    ap.add_argument("-o", "--report", metavar="FILE",
                    help="write one JSON object per probe to FILE (JSONL), including the "
                         "raw reply bytes, for later analysis")
    ap.add_argument("--no-raw", action="store_true",
                    help="omit the raw hex reply from the report (smaller file)")
    ap.add_argument("--no-progress", action="store_true",
                    help="do not draw the progress line on stderr")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.no_color:
        for k in VERDICT_MARK:
            VERDICT_MARK[k] = "[%s]" % k[:6]

    if args.function:
        candidates = args.function
    elif args.wordlist:
        candidates = load_candidates(args.wordlist)
    else:
        candidates = DEFAULT_CANDIDATES

    print("[*] target %s:%d  client=%s  %d function module(s)  threads=%d" %
          (args.host, args.port, args.client, len(candidates), args.threads))

    def probe_one(fn):
        """Run one probe on its own connection; return (fn, reply_or_exception)."""
        try:
            with RFCClient(args.host, args.port, args.route, args.timeout,
                           client=args.client, lang=args.lang,
                           program=args.program) as c:
                c.connect()
                return fn, c.probe(fn)
        except (RFCProbeError, OSError) as e:
            return fn, e

    unauth = []
    sysinfo = None
    report = open(args.report, "w") if args.report else None
    progress = Progress(len(candidates), enabled=not args.no_progress)

    def write_report(fn, reply):
        if report is None:
            return
        if isinstance(reply, Exception):
            row = {"function": fn, "verdict": "error", "code": None,
                   "message": str(reply), "values": []}
        else:
            row = reply.to_dict(function=fn, include_raw=not args.no_raw)
        report.write(json.dumps(row) + "\n")

    def handle(fn, reply):
        nonlocal sysinfo
        hit = not isinstance(reply, Exception) and reply.unauthenticated
        progress.clear()
        if isinstance(reply, RFCProbeError):
            if args.all:
                print("    %-32s \033[0;90m[error ]\033[0m %s" % (fn, reply))
        elif isinstance(reply, OSError):
            print("[!] %s: %s" % (fn, reply))
        else:
            if reply.unauthenticated:
                unauth.append(fn)
                if fn == "RFC_SYSTEM_INFO":
                    sysinfo = reply
            if reply.unauthenticated or args.all:
                print("    %-32s %s %s" % (fn, VERDICT_MARK[reply.verdict],
                                           reply.code or ""))
        write_report(fn, reply)
        progress.advance(hit)

    try:
        if args.threads > 1:
            from concurrent.futures import ThreadPoolExecutor
            # Keep output in wordlist order by resolving futures in submission order.
            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                for fn, reply in pool.map(lambda f: probe_one(f), candidates):
                    handle(fn, reply)
        else:
            for fn in candidates:
                handle(*probe_one(fn))
    finally:
        progress.close()
        if report is not None:
            report.close()

    print("\n[*] %d of %d callable unauthenticated: %s" %
          (len(unauth), len(candidates), ", ".join(unauth) or "(none)"))
    if report is not None:
        print("[*] report written to %s" % args.report)

    if sysinfo is not None:
        # The RFCSI record is the one long character value in the reply.
        rfcsi_record = max((v for _, v in sysinfo.values), key=len, default=b"")
        info = parse_rfcsi(rfcsi_record)
        print("\n[*] RFC_SYSTEM_INFO (unauthenticated):")
        for key in ("RFCSYSID", "RFCDATABS", "RFCDBSYS", "RFCSAPRL", "RFCKERNRL",
                    "RFCOPSYS", "RFCMACH", "RFCHOST", "RFCIPADDR", "RFCDEST"):
            if info.get(key):
                print("      %-11s %s" % (key, info[key]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
