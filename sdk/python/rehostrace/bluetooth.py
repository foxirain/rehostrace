"""Stateful Bluetooth host-boundary replay for public RehostRace traces.

The model intentionally stops at the host/controller boundary.  It validates
causal HCI, ACL, L2CAP, and selected upper-protocol state without pretending to
emulate a radio, controller firmware, Android's complete Bluetooth stack, or a
particular vendor module.  Target-specific adapters may project the accepted
events into their native transport after this fail-closed semantic pass.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol


PACK_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
FIXTURE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
PACK_LAYERS = {"controller", "link", "application"}


class BluetoothStateError(RuntimeError):
    """Raised when a trace violates a Bluetooth lifecycle invariant."""


def _integer(attributes: dict, key: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    value = attributes.get(key)
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        upper = "" if maximum is None else f"..{maximum}"
        raise BluetoothStateError(f"{key} must be an integer in {minimum}{upper}")
    return value


def _text(attributes: dict, key: str) -> str:
    value = attributes.get(key)
    if not isinstance(value, str) or not value:
        raise BluetoothStateError(f"{key} must be non-empty text")
    return value


def _choice(attributes: dict, key: str, choices: set[str]) -> str:
    value = _text(attributes, key)
    if value not in choices:
        raise BluetoothStateError(f"{key} must be one of {sorted(choices)}")
    return value


def _canonical_sha256(document: dict) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_protocol_pack(document: dict) -> dict:
    """Validate a declarative protocol-pack manifest.

    The manifest describes the operations and required attributes accepted by
    a code handler.  It is deliberately data-only: loading a manifest cannot
    execute plugin code.
    """

    if not isinstance(document, dict) or document.get("schema_version") != "rehostrace.bluetooth-pack/v1":
        raise ValueError("invalid Bluetooth protocol-pack schema_version")
    pack_id = document.get("pack_id")
    if not isinstance(pack_id, str) or not PACK_ID_RE.fullmatch(pack_id):
        raise ValueError("invalid Bluetooth protocol-pack id")
    protocol = document.get("protocol")
    if not isinstance(protocol, str) or not PACK_ID_RE.fullmatch(protocol):
        raise ValueError("invalid Bluetooth protocol-pack protocol id")
    if document.get("layer") not in PACK_LAYERS:
        raise ValueError("invalid Bluetooth protocol-pack layer")
    dependencies = document.get("requires", [])
    if not isinstance(dependencies, list) or len(dependencies) != len(set(dependencies)):
        raise ValueError("protocol-pack requires must be a unique list")
    if any(not isinstance(item, str) or not PACK_ID_RE.fullmatch(item) for item in dependencies):
        raise ValueError("protocol-pack dependency id is invalid")
    selectors = document.get("selectors")
    if not isinstance(selectors, list) or not selectors:
        raise ValueError("protocol-pack selectors must not be empty")
    operations: list[str] = []
    required_attributes: dict[str, list[str]] = {}
    for position, selector in enumerate(selectors):
        if not isinstance(selector, dict):
            raise ValueError(f"protocol-pack selector {position} must be an object")
        operation = selector.get("operation")
        if not isinstance(operation, str) or not PACK_ID_RE.fullmatch(operation):
            raise ValueError(f"protocol-pack selector {position} has invalid operation")
        required = selector.get("required_attributes", [])
        if not isinstance(required, list) or len(required) != len(set(required)):
            raise ValueError(f"protocol-pack selector {operation} has invalid required_attributes")
        if any(not isinstance(item, str) or not PACK_ID_RE.fullmatch(item) for item in required):
            raise ValueError(f"protocol-pack selector {operation} has invalid attribute id")
        operations.append(operation)
        required_attributes[operation] = sorted(required)
    if len(operations) != len(set(operations)):
        raise ValueError("protocol-pack operations must be unique")
    return {
        "status": "passed",
        "pack_id": pack_id,
        "protocol": protocol,
        "operations": sorted(operations),
        "required_attributes": required_attributes,
        "canonical_sha256": _canonical_sha256(document),
    }


def validate_profile_catalog(document: dict) -> dict:
    """Validate the data-only registry of implemented and explicitly open profiles."""

    if document.get("schema_version") != "rehostrace.bluetooth-profile-catalog/v1":
        raise ValueError("unsupported Bluetooth profile catalog schema")
    profiles = document.get("profiles")
    gaps = document.get("open_profiles")
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("Bluetooth profile catalog must contain profiles")
    if not isinstance(gaps, list):
        raise ValueError("Bluetooth profile catalog open_profiles must be a list")
    ids: set[str] = set()
    for record in [*profiles, *gaps]:
        record_id = record.get("id") if isinstance(record, dict) else None
        if (
            not isinstance(record_id, str)
            or not FIXTURE_NAME_RE.fullmatch(record_id)
            or record_id in ids
        ):
            raise ValueError("Bluetooth profile catalog ids must be unique safe names")
        ids.add(record_id)
    for profile in profiles:
        if not isinstance(profile.get("transport"), str) or not profile["transport"]:
            raise ValueError(f"profile {profile['id']} has no transport")
        packs = profile.get("packs")
        if not isinstance(packs, list) or not packs:
            raise ValueError(f"profile {profile['id']} has no protocol packs")
        names = [profile.get("trace"), *packs]
        if any(
            not isinstance(name, str) or not FIXTURE_NAME_RE.fullmatch(name)
            for name in names
        ):
            raise ValueError(f"profile {profile['id']} contains an unsafe fixture path")
        states = profile.get("state_machines")
        if not isinstance(states, list) or not states or any(
            not isinstance(state, str) or not state for state in states
        ):
            raise ValueError(f"profile {profile['id']} has invalid state_machines")
    for gap in gaps:
        if not isinstance(gap.get("reason"), str) or not gap["reason"]:
            raise ValueError(f"open profile {gap['id']} has no reason")
    return copy.deepcopy(document)


class BluetoothProtocolPack(Protocol):
    pack_id: str
    operations: frozenset[str]

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        """Apply one event after manifest and causal-order validation."""

    def finalize(self, model: "BluetoothCoreAdapter") -> dict:
        """Return pack summary or reject incomplete terminal state."""


@dataclass
class _PackRegistration:
    handler: BluetoothProtocolPack
    manifest: dict
    validation: dict


class HciProtocolPack:
    pack_id = "public.bluetooth.hci-core.v1"
    operations = frozenset(
        {
            "hci.controller.ready",
            "hci.command.sent",
            "hci.command.status",
            "hci.command.complete",
            "hci.connection.complete",
            "hci.le.connection.complete",
            "hci.authentication.complete",
            "hci.encryption.change",
            "hci.acl.fragment",
            "hci.disconnection.complete",
        }
    )

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        operation = event["boundary"]["operation"]
        attributes = event["attributes"]
        if operation == "hci.controller.ready":
            if model.controller_ready:
                raise BluetoothStateError("controller was initialized twice")
            model.controller_ready = True
            model.command_credits = _integer(attributes, "command_credits", maximum=255)
        elif operation == "hci.command.sent":
            model._require_controller()
            command_id = _text(attributes, "command_id")
            opcode = _integer(attributes, "opcode", maximum=0xFFFF)
            if model.command_credits == 0:
                raise BluetoothStateError("HCI command sent with no controller credit")
            if command_id in model.pending_commands:
                raise BluetoothStateError(f"duplicate pending HCI command: {command_id}")
            model.command_credits -= 1
            model.pending_commands[command_id] = opcode
        elif operation in {"hci.command.status", "hci.command.complete"}:
            command_id = _text(attributes, "command_id")
            opcode = _integer(attributes, "opcode", maximum=0xFFFF)
            if model.pending_commands.get(command_id) != opcode:
                raise BluetoothStateError(f"HCI completion does not match pending command: {command_id}")
            if _integer(attributes, "status", maximum=255) != 0:
                raise BluetoothStateError(f"fixture contains failed HCI command: {command_id}")
            del model.pending_commands[command_id]
            model.command_credits = _integer(attributes, "command_credits", maximum=255)
        elif operation in {"hci.connection.complete", "hci.le.connection.complete"}:
            model._require_controller()
            if _integer(attributes, "status", maximum=255) != 0:
                raise BluetoothStateError("fixture contains failed HCI connection")
            handle = _integer(attributes, "handle", maximum=0x0EFF)
            if handle in model.connections and model.connections[handle]["state"] == "connected":
                raise BluetoothStateError(f"connection handle already active: {handle:#x}")
            connection = {
                "state": "connected",
                "address_token": _text(attributes, "address_token"),
                "authenticated": False,
                "encrypted": False,
            }
            if operation == "hci.connection.complete":
                connection["link_type"] = _choice(
                    attributes, "link_type", {"acl", "sco", "esco"}
                )
            else:
                try:
                    peer_address = bytes.fromhex(_text(attributes, "peer_address_hex"))
                except ValueError as error:
                    raise BluetoothStateError(
                        "LE peer_address_hex must contain whole hexadecimal bytes"
                    ) from error
                if len(peer_address) != 6:
                    raise BluetoothStateError("LE peer_address_hex must contain six bytes")
                interval = _integer(
                    attributes, "connection_interval", minimum=0x0006, maximum=0x0C80
                )
                latency = _integer(
                    attributes, "connection_latency", maximum=0x01F3
                )
                timeout = _integer(
                    attributes, "supervision_timeout", minimum=0x000A, maximum=0x0C80
                )
                if timeout * 8 <= (1 + latency) * interval * 2:
                    raise BluetoothStateError(
                        "LE supervision timeout does not exceed the connection latency bound"
                    )
                connection.update(
                    link_type="le-acl",
                    role=_choice(attributes, "role", {"central", "peripheral"}),
                    peer_address_type=_choice(
                        attributes, "peer_address_type", {"public", "random"}
                    ),
                    peer_address_token=_text(attributes, "peer_address_token"),
                    connection_interval=interval,
                    connection_latency=latency,
                    supervision_timeout=timeout,
                    clock_accuracy=_integer(attributes, "clock_accuracy", maximum=7),
                )
            model.connections[handle] = connection
        elif operation == "hci.authentication.complete":
            connection = model._connection(attributes)
            if _integer(attributes, "status", maximum=255) != 0:
                raise BluetoothStateError("fixture contains failed authentication")
            connection["authenticated"] = True
        elif operation == "hci.encryption.change":
            connection = model._connection(attributes)
            if not connection["authenticated"]:
                raise BluetoothStateError("encryption enabled before authentication")
            if _integer(attributes, "status", maximum=255) != 0:
                raise BluetoothStateError("fixture contains failed encryption change")
            connection["encrypted"] = bool(_integer(attributes, "enabled", maximum=1))
        elif operation == "hci.acl.fragment":
            model._acl_fragment(attributes)
        elif operation == "hci.disconnection.complete":
            connection = model._connection(attributes)
            if _integer(attributes, "status", maximum=255) != 0:
                raise BluetoothStateError("fixture contains failed disconnection")
            handle = _integer(attributes, "handle", maximum=0x0EFF)
            reason = _integer(attributes, "reason", maximum=255)
            connection["state"] = "disconnected"
            connection["disconnect_reason"] = reason
            for channel in model.channels.values():
                if channel["handle"] == handle and channel["state"] != "closed":
                    channel["state"] = "link-lost"
            for key in list(model.outstanding_avdtp):
                if key[0] == handle:
                    del model.outstanding_avdtp[key]
            for key in list(model.fragment_buffers):
                if key[0] == handle:
                    del model.fragment_buffers[key]
        return model._observation(event)


class L2capProtocolPack:
    pack_id = "public.bluetooth.l2cap-core.v1"
    operations = frozenset(
        {
            "l2cap.connection.request",
            "l2cap.connection.response",
            "l2cap.config.request",
            "l2cap.config.response",
            "l2cap.channel.open",
            "l2cap.disconnect.request",
            "l2cap.disconnect.response",
        }
    )

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        operation = event["boundary"]["operation"]
        attributes = event["attributes"]
        connection = model._connection(attributes)
        handle = _integer(attributes, "handle", maximum=0x0EFF)
        local_cid = _integer(attributes, "local_cid", minimum=0x0040, maximum=0xFFFF)
        key = (handle, local_cid)
        if operation != "l2cap.channel.open":
            _integer(attributes, "identifier", minimum=1, maximum=255)
        if operation == "l2cap.connection.request":
            model._consume_sdu(attributes)
            if key in model.channels and model.channels[key]["state"] != "closed":
                raise BluetoothStateError("L2CAP local CID is already active")
            model.channels[key] = {
                "handle": handle,
                "local_cid": local_cid,
                "remote_cid": None,
                "psm": _integer(attributes, "psm", minimum=1, maximum=0xFFFF),
                "state": "waiting-response",
                "pending_config": set(),
                "configured": set(),
            }
        else:
            channel = model.channels.get(key)
            if channel is None:
                raise BluetoothStateError("L2CAP event references an unknown channel")
            if connection["state"] != "connected":
                raise BluetoothStateError("L2CAP event references a disconnected handle")
            if operation != "l2cap.channel.open":
                model._consume_sdu(attributes)
            if operation == "l2cap.connection.response":
                if channel["state"] != "waiting-response":
                    raise BluetoothStateError("unexpected L2CAP connection response")
                result = _choice(attributes, "result", {"pending", "success", "refused"})
                remote_cid = _integer(attributes, "remote_cid", minimum=0x0040, maximum=0xFFFF)
                if channel["remote_cid"] not in {None, remote_cid}:
                    raise BluetoothStateError("L2CAP response changed the remote CID")
                channel["remote_cid"] = remote_cid
                if result == "success":
                    channel["state"] = "configuring"
                elif result == "refused":
                    channel["state"] = "closed"
            elif operation == "l2cap.config.request":
                if channel["state"] != "configuring":
                    raise BluetoothStateError("L2CAP config request outside configuration state")
                initiator = _choice(attributes, "initiator", {"local", "peer"})
                if initiator in channel["pending_config"] or initiator in channel["configured"]:
                    raise BluetoothStateError("duplicate L2CAP config request")
                channel["pending_config"].add(initiator)
            elif operation == "l2cap.config.response":
                if channel["state"] != "configuring":
                    raise BluetoothStateError("L2CAP config response outside configuration state")
                initiator = _choice(attributes, "initiator", {"local", "peer"})
                if initiator not in channel["pending_config"]:
                    raise BluetoothStateError("L2CAP config response has no matching request")
                if _choice(attributes, "result", {"success", "unacceptable", "rejected"}) != "success":
                    raise BluetoothStateError("fixture contains rejected L2CAP configuration")
                channel["pending_config"].remove(initiator)
                channel["configured"].add(initiator)
                if channel["configured"] == {"local", "peer"}:
                    channel["state"] = "open"
            elif operation == "l2cap.channel.open":
                if channel["state"] != "open" or channel["pending_config"]:
                    raise BluetoothStateError("L2CAP channel-open assertion failed")
            elif operation == "l2cap.disconnect.request":
                if channel["state"] != "open":
                    raise BluetoothStateError("L2CAP disconnect requested for a non-open channel")
                if model._channel_has_outstanding_avdtp(handle, local_cid):
                    raise BluetoothStateError("L2CAP disconnect with outstanding AVDTP transaction")
                channel["state"] = "disconnecting"
            elif operation == "l2cap.disconnect.response":
                if channel["state"] != "disconnecting":
                    raise BluetoothStateError("L2CAP disconnect response without request")
                channel["state"] = "closed"
        return model._observation(event)


class AvdtpProtocolPack:
    pack_id = "public.bluetooth.avdtp-signaling.v1"
    operations = frozenset({"avdtp.command", "avdtp.response"})
    signals = {
        "discover",
        "get-capabilities",
        "set-configuration",
        "open",
        "start",
        "suspend",
        "close",
        "abort",
        "security-control",
    }
    signal_ids = {
        "discover": 1,
        "get-capabilities": 2,
        "set-configuration": 3,
        "open": 6,
        "start": 7,
        "close": 8,
        "suspend": 9,
        "abort": 10,
        "security-control": 11,
    }

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        operation = event["boundary"]["operation"]
        attributes = event["attributes"]
        channel = model._channel(attributes, require_open=True)
        if channel["psm"] != 0x0019:
            raise BluetoothStateError("AVDTP event requires an L2CAP PSM 0x0019 channel")
        model._consume_sdu(attributes)
        handle = channel["handle"]
        local_cid = channel["local_cid"]
        label = _integer(attributes, "transaction_label", maximum=15)
        signal = _choice(attributes, "signal", self.signals)
        payload_hex = _text(attributes, "payload_hex")
        try:
            payload = bytes.fromhex(payload_hex)
        except ValueError as error:
            raise BluetoothStateError("AVDTP payload_hex must contain whole hexadecimal bytes") from error
        if len(payload) < 2:
            raise BluetoothStateError("AVDTP payload must include its two-byte signaling header")
        expected_message_type = 0 if operation == "avdtp.command" else {
            "accept": 2,
            "reject": 3,
            "general-reject": 1,
        }[_choice(attributes, "message_type", {"accept", "reject", "general-reject"})]
        expected_header = bytes(((label << 4) | expected_message_type, self.signal_ids[signal]))
        if payload[:2] != expected_header:
            raise BluetoothStateError("AVDTP payload header does not match semantic attributes")
        key = (handle, local_cid, label)
        if operation == "avdtp.command":
            if key in model.outstanding_avdtp:
                raise BluetoothStateError("AVDTP transaction label reused before response")
            model.outstanding_avdtp[key] = signal
        else:
            if model.outstanding_avdtp.get(key) != signal:
                raise BluetoothStateError("AVDTP response does not match an outstanding command")
            message_type = _choice(attributes, "message_type", {"accept", "reject", "general-reject"})
            del model.outstanding_avdtp[key]
            session_key = (handle, local_cid)
            session = model.avdtp_sessions.setdefault(session_key, {"state": "idle", "last_signal": None})
            session["last_signal"] = signal
            if message_type == "accept":
                transitions = {
                    "discover": "discovered",
                    "set-configuration": "configured",
                    "open": "open",
                    "start": "streaming",
                    "suspend": "open",
                    "close": "idle",
                    "abort": "idle",
                }
                session["state"] = transitions.get(signal, session["state"])
        return model._observation(event)


class SdpProtocolPack:
    """SDP request/response matching over an open L2CAP PSM 0x0001 channel."""

    pack_id = "public.bluetooth.sdp.v1"
    operations = frozenset({"sdp.request", "sdp.response"})
    request_ids = {
        "service-search": (0x02, 0x03),
        "service-attribute": (0x04, 0x05),
        "service-search-attribute": (0x06, 0x07),
    }

    @staticmethod
    def _decode(attributes: dict) -> tuple[bytes, int, int]:
        payload_hex = _text(attributes, "payload_hex")
        try:
            payload = bytes.fromhex(payload_hex)
        except ValueError as error:
            raise BluetoothStateError("SDP payload_hex must contain whole hexadecimal bytes") from error
        if len(payload) < 5:
            raise BluetoothStateError("SDP PDU is shorter than its five-byte header")
        transaction_id = int.from_bytes(payload[1:3], "big")
        parameter_length = int.from_bytes(payload[3:5], "big")
        if parameter_length != len(payload) - 5:
            raise BluetoothStateError("SDP parameter length does not match payload")
        if transaction_id != _integer(attributes, "transaction_id", maximum=0xFFFF):
            raise BluetoothStateError("SDP wire/semantic transaction id mismatch")
        return payload, payload[0], transaction_id

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        operation = event["boundary"]["operation"]
        attributes = event["attributes"]
        channel = model._channel(attributes, require_open=True)
        if channel["psm"] != 0x0001:
            raise BluetoothStateError("SDP event requires an L2CAP PSM 0x0001 channel")
        model._consume_sdu(attributes)
        payload, pdu_id, transaction_id = self._decode(attributes)
        pdu = _choice(attributes, "pdu", set(self.request_ids))
        request_id, response_id = self.request_ids[pdu]
        key = (channel["handle"], channel["local_cid"])
        if operation == "sdp.request":
            if pdu_id != request_id:
                raise BluetoothStateError("SDP request PDU id does not match semantic operation")
            if key in model.sdp_outstanding:
                raise BluetoothStateError("SDP allows only one outstanding request per L2CAP connection")
            model.sdp_outstanding[key] = {
                "transaction_id": transaction_id,
                "pdu": pdu,
                "response_id": response_id,
            }
        else:
            pending = model.sdp_outstanding.get(key)
            if pending is None:
                raise BluetoothStateError("SDP response has no outstanding request")
            if pending["transaction_id"] != transaction_id or pending["pdu"] != pdu:
                raise BluetoothStateError("SDP response does not match its request")
            if pdu_id not in {pending["response_id"], 0x01}:
                raise BluetoothStateError("SDP response PDU id is invalid for its request")
            model.sdp_sessions[key] = {
                "last_pdu": pdu,
                "last_transaction_id": transaction_id,
                "last_response_bytes": len(payload),
            }
            del model.sdp_outstanding[key]
        return model._observation(event)


class AttProtocolPack:
    """Basic ATT bearer transaction state used by public GATT fixtures."""

    pack_id = "public.bluetooth.att.v1"
    operations = frozenset({"att.request", "att.response"})
    methods = {
        "exchange-mtu": (0x02, 0x03),
        "find-information": (0x04, 0x05),
        "find-by-type-value": (0x06, 0x07),
        "read-by-type": (0x08, 0x09),
        "read": (0x0A, 0x0B),
        "read-blob": (0x0C, 0x0D),
        "read-multiple": (0x0E, 0x0F),
        "read-by-group-type": (0x10, 0x11),
        "write": (0x12, 0x13),
        "prepare-write": (0x16, 0x17),
        "execute-write": (0x18, 0x19),
    }
    procedure_methods = {
        "exchange-mtu": {"exchange-mtu"},
        "discover-primary-services": {"read-by-group-type"},
        "read-characteristic": {"read", "read-blob"},
        "write-characteristic": {"write", "prepare-write", "execute-write"},
    }

    @staticmethod
    def _payload(attributes: dict) -> bytes:
        try:
            payload = bytes.fromhex(_text(attributes, "payload_hex"))
        except ValueError as error:
            raise BluetoothStateError("ATT payload_hex must contain whole hexadecimal bytes") from error
        if not payload:
            raise BluetoothStateError("ATT payload must include an opcode")
        return payload

    @staticmethod
    def _validate_request_shape(method: str, payload: bytes) -> None:
        exact = {
            "exchange-mtu": {3},
            "find-information": {5},
            "read-by-type": {7, 21},
            "read": {3},
            "read-blob": {5},
            "read-by-group-type": {7, 21},
            "execute-write": {2},
        }
        if method in exact and len(payload) not in exact[method]:
            raise BluetoothStateError(f"ATT {method} request has an invalid length")
        if method == "find-by-type-value" and len(payload) < 7:
            raise BluetoothStateError("ATT find-by-type-value request is truncated")
        if method == "read-multiple" and (len(payload) < 5 or len(payload) % 2 == 0):
            raise BluetoothStateError("ATT read-multiple request has an invalid handle list")
        if method == "write" and len(payload) < 3:
            raise BluetoothStateError("ATT write request is truncated")
        if method == "prepare-write" and len(payload) < 5:
            raise BluetoothStateError("ATT prepare-write request is truncated")

    @staticmethod
    def _validate_response_shape(method: str, payload: bytes, request_opcode: int) -> None:
        if payload[0] == 0x01:
            if len(payload) != 5 or payload[1] != request_opcode:
                raise BluetoothStateError("ATT Error Response does not identify the request opcode")
            return
        exact = {"exchange-mtu": 3, "write": 1, "execute-write": 1}
        if method in exact and len(payload) != exact[method]:
            raise BluetoothStateError(f"ATT {method} response has an invalid length")
        if method == "find-information" and len(payload) < 2:
            raise BluetoothStateError("ATT find-information response is truncated")
        if method == "find-by-type-value" and (len(payload) < 5 or (len(payload) - 1) % 4):
            raise BluetoothStateError("ATT find-by-type-value response has invalid handle pairs")
        if method in {"read-by-type", "read-by-group-type"}:
            if len(payload) < 2 or payload[1] < 2 or (len(payload) - 2) % payload[1]:
                raise BluetoothStateError(f"ATT {method} response has invalid attribute records")
        if method == "prepare-write" and len(payload) < 5:
            raise BluetoothStateError("ATT prepare-write response is truncated")

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        operation = event["boundary"]["operation"]
        attributes = event["attributes"]
        model._connection(attributes)
        model._consume_sdu(attributes)
        handle = _integer(attributes, "handle", maximum=0x0EFF)
        bearer_cid = _integer(attributes, "bearer_cid", minimum=0x0004, maximum=0xFFFF)
        transaction_id = _text(attributes, "transaction_id")
        procedure_id = _text(attributes, "procedure_id")
        method = _choice(attributes, "method", set(self.methods))
        payload = self._payload(attributes)
        request_opcode, response_opcode = self.methods[method]
        key = (handle, bearer_cid)
        if operation == "att.request":
            if payload[0] != request_opcode:
                raise BluetoothStateError("ATT request opcode does not match semantic method")
            self._validate_request_shape(method, payload)
            if key in model.att_outstanding:
                raise BluetoothStateError("basic ATT bearer already has an outstanding request")
            procedure = model.gatt_procedures.get((handle, bearer_cid))
            if procedure is None or procedure["procedure_id"] != procedure_id:
                raise BluetoothStateError("ATT request is not owned by an active GATT procedure")
            if method not in self.procedure_methods[procedure["procedure"]]:
                raise BluetoothStateError("ATT method is invalid for the active GATT procedure")
            if transaction_id in model.att_completed:
                raise BluetoothStateError("ATT transaction id was already completed")
            model.att_outstanding[key] = {
                "transaction_id": transaction_id,
                "procedure_id": procedure_id,
                "method": method,
                "response_opcode": response_opcode,
                "request_payload": payload.hex(),
            }
        else:
            pending = model.att_outstanding.get(key)
            if pending is None:
                raise BluetoothStateError("ATT response has no outstanding request")
            if pending["transaction_id"] != transaction_id or pending["procedure_id"] != procedure_id:
                raise BluetoothStateError("ATT response identity does not match its request")
            if pending["method"] != method or payload[0] not in {pending["response_opcode"], 0x01}:
                raise BluetoothStateError("ATT response opcode/method does not match its request")
            self._validate_response_shape(method, payload, request_opcode)
            if method == "exchange-mtu" and payload[0] == response_opcode:
                request = bytes.fromhex(pending["request_payload"])
                if len(request) != 3 or len(payload) != 3:
                    raise BluetoothStateError("ATT Exchange MTU PDUs must contain a 16-bit MTU")
                model.att_mtu[key] = min(
                    int.from_bytes(request[1:3], "little"),
                    int.from_bytes(payload[1:3], "little"),
                )
            procedure = model.gatt_procedures[(handle, bearer_cid)]
            procedure["completed_att_transactions"] += 1
            model.att_completed[transaction_id] = {
                "handle": handle,
                "bearer_cid": bearer_cid,
                "procedure_id": procedure_id,
                "method": method,
                "response_opcode": payload[0],
            }
            del model.att_outstanding[key]
        return model._observation(event)


class GattProtocolPack:
    """Procedure-level oracle layered above ATT transactions."""

    pack_id = "public.bluetooth.gatt.v1"
    operations = frozenset({"gatt.procedure.start", "gatt.procedure.complete"})
    procedures = {
        "exchange-mtu",
        "discover-primary-services",
        "read-characteristic",
        "write-characteristic",
    }

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        operation = event["boundary"]["operation"]
        attributes = event["attributes"]
        model._connection(attributes)
        handle = _integer(attributes, "handle", maximum=0x0EFF)
        bearer_cid = _integer(attributes, "bearer_cid", minimum=0x0004, maximum=0xFFFF)
        procedure_id = _text(attributes, "procedure_id")
        procedure = _choice(attributes, "procedure", self.procedures)
        key = (handle, bearer_cid)
        if operation == "gatt.procedure.start":
            if key in model.gatt_procedures:
                raise BluetoothStateError("GATT bearer already has an active procedure")
            model.gatt_procedures[key] = {
                "procedure_id": procedure_id,
                "procedure": procedure,
                "completed_att_transactions": 0,
            }
        else:
            active = model.gatt_procedures.get(key)
            if active is None or active["procedure_id"] != procedure_id or active["procedure"] != procedure:
                raise BluetoothStateError("GATT completion does not match an active procedure")
            if _choice(attributes, "result", {"success", "error"}) != "success":
                raise BluetoothStateError("public positive fixture contains a failed GATT procedure")
            if active["completed_att_transactions"] == 0:
                raise BluetoothStateError("GATT procedure completed without an ATT transaction")
            model.gatt_history.append({**active, "handle": handle, "bearer_cid": bearer_cid})
            del model.gatt_procedures[key]
        return model._observation(event)


class BluetoothCoreAdapter:
    """Replay adapter enforcing state across HCI, ACL, L2CAP, and AVDTP."""

    boundary_domain = "bluetooth.host-boundary"

    def __init__(self, registrations: list[tuple[BluetoothProtocolPack, dict]]):
        if not registrations:
            raise ValueError("at least one Bluetooth protocol pack is required")
        self.registrations: dict[str, _PackRegistration] = {}
        self.operation_handlers: dict[str, BluetoothProtocolPack] = {}
        for handler, manifest in registrations:
            validation = validate_protocol_pack(manifest)
            if validation["pack_id"] != handler.pack_id:
                raise ValueError("protocol-pack manifest/handler id mismatch")
            if set(validation["operations"]) != set(handler.operations):
                raise ValueError(f"protocol-pack operation drift: {handler.pack_id}")
            if handler.pack_id in self.registrations:
                raise ValueError(f"duplicate protocol-pack id: {handler.pack_id}")
            for dependency in manifest.get("requires", []):
                if dependency not in {item[0].pack_id for item in registrations}:
                    raise ValueError(f"missing protocol-pack dependency: {dependency}")
            for operation in handler.operations:
                if operation in self.operation_handlers:
                    raise ValueError(f"duplicate Bluetooth operation handler: {operation}")
                self.operation_handlers[operation] = handler
            self.registrations[handler.pack_id] = _PackRegistration(handler, copy.deepcopy(manifest), validation)

        self.controller_ready = False
        self.command_credits = 0
        self.pending_commands: dict[str, int] = {}
        self.connections: dict[int, dict] = {}
        self.fragment_buffers: dict[tuple[int, str], dict] = {}
        self.completed_sdus: dict[str, dict] = {}
        self.consumed_sdus: set[str] = set()
        self.channels: dict[tuple[int, int], dict] = {}
        self.outstanding_avdtp: dict[tuple[int, int, int], str] = {}
        self.avdtp_sessions: dict[tuple[int, int], dict] = {}
        self.sdp_outstanding: dict[tuple[int, int], dict] = {}
        self.sdp_sessions: dict[tuple[int, int], dict] = {}
        self.att_outstanding: dict[tuple[int, int], dict] = {}
        self.att_completed: dict[str, dict] = {}
        self.att_mtu: dict[tuple[int, int], int] = {}
        self.gatt_procedures: dict[tuple[int, int], dict] = {}
        self.gatt_history: list[dict] = []
        self.extension_state: dict[str, dict] = {}
        self.event_count = 0

    def _required_attributes(self, operation: str) -> list[str]:
        handler = self.operation_handlers[operation]
        return self.registrations[handler.pack_id].validation["required_attributes"][operation]

    def _require_controller(self) -> None:
        if not self.controller_ready:
            raise BluetoothStateError("HCI controller is not ready")

    def _connection(self, attributes: dict) -> dict:
        handle = _integer(attributes, "handle", maximum=0x0EFF)
        connection = self.connections.get(handle)
        if connection is None or connection["state"] != "connected":
            raise BluetoothStateError(f"unknown or disconnected HCI handle: {handle:#x}")
        return connection

    def _channel(self, attributes: dict, *, require_open: bool) -> dict:
        self._connection(attributes)
        handle = _integer(attributes, "handle", maximum=0x0EFF)
        local_cid = _integer(attributes, "local_cid", minimum=0x0040, maximum=0xFFFF)
        channel = self.channels.get((handle, local_cid))
        if channel is None:
            raise BluetoothStateError("unknown L2CAP channel")
        if require_open and channel["state"] != "open":
            raise BluetoothStateError("upper-protocol event requires an open L2CAP channel")
        return channel

    def _acl_fragment(self, attributes: dict) -> None:
        self._connection(attributes)
        handle = _integer(attributes, "handle", maximum=0x0EFF)
        direction = _choice(attributes, "direction", {"host-to-controller", "controller-to-host"})
        boundary = _choice(attributes, "packet_boundary", {"complete", "start", "continuation"})
        fragment_length = _integer(attributes, "fragment_length", maximum=0xFFFF)
        key = (handle, direction)
        if boundary in {"complete", "start"}:
            if key in self.fragment_buffers:
                raise BluetoothStateError("new ACL SDU started before previous reassembly completed")
            sdu_id = _text(attributes, "sdu_id")
            cid = _integer(attributes, "cid", maximum=0xFFFF)
            sdu_length = _integer(attributes, "sdu_length", maximum=0xFFFF)
            if sdu_id in self.completed_sdus or sdu_id in self.consumed_sdus:
                raise BluetoothStateError(f"duplicate ACL SDU id: {sdu_id}")
            if fragment_length > sdu_length:
                raise BluetoothStateError("ACL fragment exceeds declared SDU length")
            if boundary == "complete" and fragment_length != sdu_length:
                raise BluetoothStateError("complete ACL packet does not contain the entire SDU")
            remaining = sdu_length - fragment_length
            record = {"handle": handle, "direction": direction, "cid": cid, "sdu_length": sdu_length}
            if remaining:
                if boundary != "start":
                    raise BluetoothStateError("partial ACL SDU must use start packet boundary")
                self.fragment_buffers[key] = {**record, "sdu_id": sdu_id, "remaining": remaining}
            else:
                self.completed_sdus[sdu_id] = record
        else:
            buffer = self.fragment_buffers.get(key)
            if buffer is None:
                raise BluetoothStateError("ACL continuation has no active reassembly")
            if fragment_length == 0 or fragment_length > buffer["remaining"]:
                raise BluetoothStateError("ACL continuation length is invalid")
            buffer["remaining"] -= fragment_length
            if buffer["remaining"] == 0:
                self.completed_sdus[buffer["sdu_id"]] = {
                    item: buffer[item] for item in ("handle", "direction", "cid", "sdu_length")
                }
                del self.fragment_buffers[key]

    def _consume_sdu(self, attributes: dict) -> None:
        sdu_id = _text(attributes, "sdu_id")
        record = self.completed_sdus.get(sdu_id)
        if record is None:
            raise BluetoothStateError(f"semantic event has no completed ACL SDU: {sdu_id}")
        handle = _integer(attributes, "handle", maximum=0x0EFF)
        if record["handle"] != handle:
            raise BluetoothStateError("semantic event/ACL SDU handle mismatch")
        direction = attributes.get("direction")
        if direction is not None and record["direction"] != direction:
            raise BluetoothStateError("semantic event/ACL SDU direction mismatch")
        wire_cid = attributes.get("wire_cid")
        if wire_cid is not None and record["cid"] != wire_cid:
            raise BluetoothStateError("semantic event/ACL SDU CID mismatch")
        self.consumed_sdus.add(sdu_id)
        del self.completed_sdus[sdu_id]

    def _channel_has_outstanding_avdtp(self, handle: int, local_cid: int) -> bool:
        return any(key[:2] == (handle, local_cid) for key in self.outstanding_avdtp)

    def _observation(self, event: dict) -> dict:
        self.event_count += 1
        return {
            "event_id": event["id"],
            "operation": event["boundary"]["operation"],
            "active_connections": sum(item["state"] == "connected" for item in self.connections.values()),
            "open_channels": sum(item["state"] == "open" for item in self.channels.values()),
            "pending_acl_reassemblies": len(self.fragment_buffers),
            "outstanding_avdtp": len(self.outstanding_avdtp),
        }

    def dispatch(self, event: dict) -> dict:
        boundary = event.get("boundary", {})
        if boundary.get("domain") != self.boundary_domain:
            raise BluetoothStateError(f"unsupported Bluetooth boundary domain: {boundary.get('domain')!r}")
        operation = boundary.get("operation")
        handler = self.operation_handlers.get(operation)
        if handler is None:
            raise BluetoothStateError(f"unsupported Bluetooth operation: {operation!r}")
        attributes = event.get("attributes")
        if not isinstance(attributes, dict):
            raise BluetoothStateError("Bluetooth event attributes must be an object")
        missing = [key for key in self._required_attributes(operation) if key not in attributes]
        if missing:
            raise BluetoothStateError(f"Bluetooth event is missing required attributes: {missing}")
        return handler.apply(self, event)

    def summary(self) -> dict:
        if self.pending_commands:
            raise BluetoothStateError("replay ended with pending HCI commands")
        if self.fragment_buffers:
            raise BluetoothStateError("replay ended with incomplete ACL reassembly")
        if self.completed_sdus:
            raise BluetoothStateError("replay ended with unconsumed ACL SDUs")
        if self.outstanding_avdtp:
            raise BluetoothStateError("replay ended with outstanding AVDTP transactions")
        if self.sdp_outstanding:
            raise BluetoothStateError("replay ended with outstanding SDP transactions")
        if self.att_outstanding:
            raise BluetoothStateError("replay ended with outstanding ATT transactions")
        if self.gatt_procedures:
            raise BluetoothStateError("replay ended with active GATT procedures")
        extension_summaries = {}
        for pack_id, registration in sorted(self.registrations.items()):
            finalize = getattr(registration.handler, "finalize", None)
            if finalize is not None:
                extension_summaries[pack_id] = finalize(self)
        return {
            "status": "passed",
            "event_count": self.event_count,
            "controller_ready": self.controller_ready,
            "command_credits": self.command_credits,
            "connections": {
                f"0x{handle:04x}": copy.deepcopy(record)
                for handle, record in sorted(self.connections.items())
            },
            "channels": {
                f"0x{handle:04x}/0x{cid:04x}": {
                    key: sorted(value) if isinstance(value, set) else copy.deepcopy(value)
                    for key, value in record.items()
                }
                for (handle, cid), record in sorted(self.channels.items())
            },
            "avdtp_sessions": {
                f"0x{handle:04x}/0x{cid:04x}": copy.deepcopy(record)
                for (handle, cid), record in sorted(self.avdtp_sessions.items())
            },
            "sdp_sessions": {
                f"0x{handle:04x}/0x{cid:04x}": copy.deepcopy(record)
                for (handle, cid), record in sorted(self.sdp_sessions.items())
            },
            "att": {
                "negotiated_mtu": {
                    f"0x{handle:04x}/0x{cid:04x}": mtu
                    for (handle, cid), mtu in sorted(self.att_mtu.items())
                },
                "completed_transactions": copy.deepcopy(self.att_completed),
            },
            "gatt_history": copy.deepcopy(self.gatt_history),
            "extensions": extension_summaries,
            "protocol_packs": {
                pack_id: registration.validation["canonical_sha256"]
                for pack_id, registration in sorted(self.registrations.items())
            },
        }


def default_bluetooth_registrations(manifests: list[dict]) -> list[tuple[BluetoothProtocolPack, dict]]:
    from .bluetooth_registry import built_in_bluetooth_registry

    return built_in_bluetooth_registry().resolve(manifests)
