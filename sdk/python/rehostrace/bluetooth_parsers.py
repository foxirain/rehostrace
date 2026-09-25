"""Bounded Bluetooth packet parsers for offline harnesses.

The parsers cover representative framing needed by public experiments.  They
are deliberately strict and incomplete: unsupported packet forms are rejected
instead of guessed.  Each successful parse returns stable semantic feature
tokens suitable for coverage-guided campaigns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


class PacketParseError(ValueError):
    """A packet is truncated, malformed, or outside the implemented subset."""


@dataclass(frozen=True)
class ParsedPacket:
    protocol: str
    fields: dict
    features: frozenset[str]


def _exact(data: bytes, size: int, label: str) -> None:
    if len(data) != size:
        raise PacketParseError(f"{label} must be exactly {size} bytes")


def parse_smp(data: bytes) -> ParsedPacket:
    if not data:
        raise PacketParseError("SMP packet is empty")
    opcode = data[0]
    sizes = {
        0x01: (7, "pairing-request"),
        0x02: (7, "pairing-response"),
        0x03: (17, "pairing-confirm"),
        0x04: (17, "pairing-random"),
        0x05: (2, "pairing-failed"),
        0x06: (17, "encryption-information"),
        0x07: (11, "master-identification"),
        0x08: (17, "identity-information"),
        0x09: (8, "identity-address-information"),
        0x0A: (17, "signing-information"),
        0x0B: (2, "security-request"),
        0x0C: (65, "public-key"),
        0x0D: (17, "dhkey-check"),
        0x0E: (2, "keypress-notification"),
    }
    if opcode not in sizes:
        raise PacketParseError("unsupported SMP opcode")
    size, name = sizes[opcode]
    _exact(data, size, f"SMP {name}")
    fields = {"opcode": opcode, "pdu": name, "payload_hex": data[1:].hex()}
    features = {"smp:framed", f"smp:opcode:{opcode:02x}", f"smp:pdu:{name}"}
    if opcode in {0x01, 0x02}:
        io_capability, oob, auth, key_size, initiator_keys, responder_keys = data[1:7]
        if io_capability > 4 or oob > 1 or not 7 <= key_size <= 16:
            raise PacketParseError("SMP pairing fields are outside the implemented bounds")
        fields.update(
            io_capability=io_capability,
            oob=oob,
            auth_requirements=auth,
            max_key_size=key_size,
            initiator_keys=initiator_keys,
            responder_keys=responder_keys,
        )
        features.add(f"smp:key-size:{key_size}")
    return ParsedPacket("smp", fields, frozenset(features))


def parse_rfcomm(data: bytes) -> ParsedPacket:
    if len(data) < 4:
        raise PacketParseError("RFCOMM frame is truncated")
    address, control, first_length = data[:3]
    if not address & 0x01:
        raise PacketParseError("RFCOMM address extension bit is not set")
    header_length = 3
    if first_length & 0x01:
        payload_length = first_length >> 1
        length_form = "short"
    else:
        if len(data) < 5:
            raise PacketParseError("RFCOMM long length is truncated")
        payload_length = (first_length >> 1) | (data[3] << 7)
        header_length = 4
        length_form = "long"
    if payload_length > 32767:
        raise PacketParseError("RFCOMM payload length exceeds the implemented bound")
    if len(data) != header_length + payload_length + 1:
        raise PacketParseError("RFCOMM declared length does not match the frame")
    frame_type = control & 0xEF
    names = {0x2F: "sabm", 0x63: "ua", 0x0F: "dm", 0x43: "disc", 0xEF: "uih"}
    name = names.get(frame_type, "other")
    return ParsedPacket(
        "rfcomm",
        {
            "dlci": address >> 2,
            "command_response": bool(address & 0x02),
            "poll_final": bool(control & 0x10),
            "frame_type": name,
            "payload_length": payload_length,
            "payload_hex": data[header_length:-1].hex(),
            "fcs": data[-1],
        },
        frozenset({"rfcomm:framed", f"rfcomm:length:{length_form}", f"rfcomm:type:{name}"}),
    )


def parse_avrcp(data: bytes) -> ParsedPacket:
    if len(data) < 6:
        raise PacketParseError("AVCTP/AVRCP packet is truncated")
    avctp = data[0]
    packet_type = (avctp >> 2) & 0x03
    if packet_type != 0:
        raise PacketParseError("only single-packet AVCTP is implemented")
    pid = int.from_bytes(data[1:3], "big")
    ctype, subunit, opcode = data[3:6]
    if pid != 0x110E:
        raise PacketParseError("AVCTP PID is not the remote-control profile")
    return ParsedPacket(
        "avrcp",
        {
            "transaction_label": avctp >> 4,
            "command_response": bool(avctp & 0x02),
            "invalid_profile": bool(avctp & 0x01),
            "pid": pid,
            "ctype_or_response": ctype,
            "subunit": subunit,
            "opcode": opcode,
            "operands_hex": data[6:].hex(),
        },
        frozenset({"avctp:single", "avrcp:framed", f"avrcp:opcode:{opcode:02x}"}),
    )


def parse_hfp_at(data: bytes) -> ParsedPacket:
    if not 2 <= len(data) <= 4096 or b"\x00" in data:
        raise PacketParseError("HFP AT line length or encoding is invalid")
    try:
        line = data.decode("ascii").strip("\r\n")
    except UnicodeDecodeError as error:
        raise PacketParseError("HFP AT line is not ASCII") from error
    if not line:
        raise PacketParseError("HFP AT line is empty")
    if line.startswith("AT"):
        body = line[2:]
        name, separator, arguments = body.partition("=")
        if not name:
            name = "attention"
        direction = "command"
        fields = {"direction": direction, "name": name, "arguments": arguments if separator else ""}
    elif line in {"OK", "ERROR"} or line.startswith(("+CME ERROR", "+CMS ERROR", "+")):
        direction = "response"
        name, separator, arguments = line.partition(":")
        fields = {"direction": direction, "name": name, "arguments": arguments.strip() if separator else ""}
    else:
        raise PacketParseError("HFP line is neither an AT command nor response")
    return ParsedPacket("hfp", fields, frozenset({"hfp:ascii", f"hfp:{direction}", f"hfp:name:{fields['name']}"}))


def parse_a2dp_rtp(data: bytes) -> ParsedPacket:
    if len(data) < 12:
        raise PacketParseError("A2DP RTP packet is truncated")
    version = data[0] >> 6
    if version != 2:
        raise PacketParseError("A2DP RTP version is not 2")
    padding = bool(data[0] & 0x20)
    extension = bool(data[0] & 0x10)
    csrc_count = data[0] & 0x0F
    header_length = 12 + 4 * csrc_count
    if len(data) < header_length:
        raise PacketParseError("A2DP RTP CSRC list is truncated")
    if extension:
        if len(data) < header_length + 4:
            raise PacketParseError("A2DP RTP extension is truncated")
        extension_words = int.from_bytes(data[header_length + 2 : header_length + 4], "big")
        header_length += 4 + extension_words * 4
        if len(data) < header_length:
            raise PacketParseError("A2DP RTP extension body is truncated")
    payload_end = len(data)
    if padding:
        padding_length = data[-1]
        if padding_length == 0 or padding_length > len(data) - header_length:
            raise PacketParseError("A2DP RTP padding is invalid")
        payload_end -= padding_length
    if payload_end <= header_length:
        raise PacketParseError("A2DP RTP media payload is empty")
    payload_type = data[1] & 0x7F
    return ParsedPacket(
        "a2dp-rtp",
        {
            "marker": bool(data[1] & 0x80),
            "payload_type": payload_type,
            "sequence": int.from_bytes(data[2:4], "big"),
            "timestamp": int.from_bytes(data[4:8], "big"),
            "ssrc": int.from_bytes(data[8:12], "big"),
            "header_length": header_length,
            "payload_length": payload_end - header_length,
        },
        frozenset({"rtp:version:2", f"rtp:payload-type:{payload_type}", f"rtp:csrc-count:{csrc_count}", f"rtp:extension:{int(extension)}"}),
    )


def parse_le_iso(data: bytes) -> ParsedPacket:
    if len(data) < 4:
        raise PacketParseError("HCI ISO packet is truncated")
    handle_flags = int.from_bytes(data[:2], "little")
    length_flags = int.from_bytes(data[2:4], "little")
    handle = handle_flags & 0x0FFF
    packet_boundary = (handle_flags >> 12) & 0x03
    timestamp_flag = bool(handle_flags & 0x4000)
    data_length = length_flags & 0x3FFF
    packet_status = (length_flags >> 14) & 0x03
    if len(data) != 4 + data_length:
        raise PacketParseError("HCI ISO declared length does not match packet")
    minimum = 8 if timestamp_flag else 4
    if data_length < minimum:
        raise PacketParseError("HCI ISO load header is truncated")
    offset = 4
    timestamp = None
    if timestamp_flag:
        timestamp = int.from_bytes(data[offset : offset + 4], "little")
        offset += 4
    packet_sequence = int.from_bytes(data[offset : offset + 2], "little")
    sdu_length_status = int.from_bytes(data[offset + 2 : offset + 4], "little")
    sdu_length = sdu_length_status & 0x3FFF
    payload = data[offset + 4 :]
    if packet_boundary in {0, 2} and sdu_length > len(payload):
        raise PacketParseError("HCI ISO SDU length exceeds this complete/start fragment")
    return ParsedPacket(
        "le-iso",
        {"handle": handle, "packet_boundary": packet_boundary, "timestamp": timestamp, "packet_status": packet_status, "packet_sequence": packet_sequence, "sdu_length": sdu_length, "fragment_length": len(payload)},
        frozenset({"iso:framed", f"iso:pb:{packet_boundary}", f"iso:timestamp:{int(timestamp_flag)}", f"iso:status:{packet_status}"}),
    )


class BluetoothPacketParserRegistry:
    """Explicit registry; protocol names cannot import parser code."""

    def __init__(self) -> None:
        self._parsers: dict[str, Callable[[bytes], ParsedPacket]] = {}

    def register(self, protocol: str, parser: Callable[[bytes], ParsedPacket]) -> None:
        if not isinstance(protocol, str) or not protocol or protocol in self._parsers or not callable(parser):
            raise ValueError("invalid or duplicate packet parser registration")
        self._parsers[protocol] = parser

    def parse(self, protocol: str, data: bytes) -> ParsedPacket:
        parser = self._parsers.get(protocol)
        if parser is None:
            raise ValueError(f"no trusted parser registered for protocol: {protocol!r}")
        if not isinstance(data, bytes):
            raise TypeError("packet input must be bytes")
        return parser(data)

    @property
    def protocols(self) -> tuple[str, ...]:
        return tuple(sorted(self._parsers))


def built_in_packet_parser_registry() -> BluetoothPacketParserRegistry:
    registry = BluetoothPacketParserRegistry()
    for protocol, parser in (
        ("smp", parse_smp),
        ("rfcomm", parse_rfcomm),
        ("avrcp", parse_avrcp),
        ("hfp-at", parse_hfp_at),
        ("a2dp-rtp", parse_a2dp_rtp),
        ("le-iso", parse_le_iso),
    ):
        registry.register(protocol, parser)
    return registry
