"""Additional Bluetooth profile lifecycle models.

These models validate semantic host-boundary events. They do not claim to be
wire decoders, controller firmware, radio models, or complete profile stacks.
"""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING

from .bluetooth import BluetoothStateError, _choice, _integer, _text

if TYPE_CHECKING:
    from .bluetooth import BluetoothCoreAdapter


def _extension(model: "BluetoothCoreAdapter", pack_id: str) -> dict:
    return model.extension_state.setdefault(pack_id, {"active": {}, "history": []})


def _session(attributes: dict) -> str:
    return _text(attributes, "session_id")


class SmpProtocolPack:
    pack_id = "public.bluetooth.smp.v1"
    operations = frozenset(
        {
            "smp.pairing.start",
            "smp.pairing.confirm",
            "smp.pairing.random",
            "smp.pairing.complete",
        }
    )

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        operation = event["boundary"]["operation"]
        attributes = event["attributes"]
        model._connection(attributes)
        state = _extension(model, self.pack_id)
        session_id = _session(attributes)
        if operation == "smp.pairing.start":
            if session_id in state["active"]:
                raise BluetoothStateError("duplicate SMP pairing session")
            state["active"][session_id] = {
                "handle": _integer(attributes, "handle", maximum=0x0EFF),
                "role": _choice(attributes, "role", {"initiator", "responder"}),
                "io_capability": _text(attributes, "io_capability"),
                "auth_requirements": _text(attributes, "auth_requirements"),
                "confirm": set(),
                "random": set(),
            }
        else:
            session = state["active"].get(session_id)
            if session is None:
                raise BluetoothStateError("SMP event references an unknown pairing session")
            if session["handle"] != _integer(attributes, "handle", maximum=0x0EFF):
                raise BluetoothStateError("SMP pairing handle drifted")
            if operation in {"smp.pairing.confirm", "smp.pairing.random"}:
                side = _choice(attributes, "side", {"local", "peer"})
                phase = "confirm" if operation.endswith("confirm") else "random"
                if side in session[phase]:
                    raise BluetoothStateError(f"duplicate SMP {phase} value")
                session[phase].add(side)
            else:
                if session["confirm"] != {"local", "peer"} or session["random"] != {
                    "local",
                    "peer",
                }:
                    raise BluetoothStateError("SMP completed before both confirm/random exchanges")
                if _choice(attributes, "result", {"success", "failure"}) != "success":
                    raise BluetoothStateError("positive SMP fixture contains pairing failure")
                if attributes.get("encrypted") is not True:
                    raise BluetoothStateError("successful SMP completion must establish encryption")
                model._connection(attributes)["encrypted"] = True
                state["history"].append(
                    {
                        key: sorted(value) if isinstance(value, set) else copy.deepcopy(value)
                        for key, value in session.items()
                    }
                )
                del state["active"][session_id]
        return model._observation(event)

    def finalize(self, model: "BluetoothCoreAdapter") -> dict:
        state = _extension(model, self.pack_id)
        if state["active"]:
            raise BluetoothStateError("replay ended with active SMP pairing sessions")
        return {"completed_pairings": len(state["history"])}


class RfcommProtocolPack:
    pack_id = "public.bluetooth.rfcomm.v1"
    operations = frozenset(
        {
            "rfcomm.session.open",
            "rfcomm.dlc.open",
            "rfcomm.credit",
            "rfcomm.data",
            "rfcomm.dlc.close",
            "rfcomm.session.close",
        }
    )

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        operation = event["boundary"]["operation"]
        attributes = event["attributes"]
        model._connection(attributes)
        state = _extension(model, self.pack_id)
        session_id = _session(attributes)
        if operation == "rfcomm.session.open":
            if session_id in state["active"]:
                raise BluetoothStateError("duplicate RFCOMM session")
            state["active"][session_id] = {
                "handle": _integer(attributes, "handle", maximum=0x0EFF),
                "role": _choice(attributes, "role", {"initiator", "responder"}),
                "dlcs": {},
                "frames": 0,
            }
        else:
            session = state["active"].get(session_id)
            if session is None:
                raise BluetoothStateError("RFCOMM event references an unknown session")
            dlci = attributes.get("dlci")
            if operation == "rfcomm.dlc.open":
                dlci = _integer(attributes, "dlci", minimum=1, maximum=63)
                if dlci in session["dlcs"]:
                    raise BluetoothStateError("RFCOMM DLCI is already open")
                credits = _integer(attributes, "initial_credits", maximum=255)
                session["dlcs"][dlci] = {
                    "credits": {"host-to-peer": credits, "peer-to-host": credits},
                    "bytes": {"host-to-peer": 0, "peer-to-host": 0},
                }
            elif operation in {"rfcomm.credit", "rfcomm.data", "rfcomm.dlc.close"}:
                dlci = _integer(attributes, "dlci", minimum=1, maximum=63)
                channel = session["dlcs"].get(dlci)
                if channel is None:
                    raise BluetoothStateError("RFCOMM event references a closed DLCI")
                if operation == "rfcomm.credit":
                    direction = _choice(
                        attributes, "direction", {"host-to-peer", "peer-to-host"}
                    )
                    channel["credits"][direction] += _integer(
                        attributes, "credits", minimum=1, maximum=255
                    )
                elif operation == "rfcomm.data":
                    direction = _choice(
                        attributes, "direction", {"host-to-peer", "peer-to-host"}
                    )
                    if channel["credits"][direction] == 0:
                        raise BluetoothStateError("RFCOMM data sent without credit")
                    channel["credits"][direction] -= 1
                    channel["bytes"][direction] += _integer(
                        attributes, "length", minimum=1, maximum=32767
                    )
                    session["frames"] += 1
                else:
                    del session["dlcs"][dlci]
            else:
                if session["dlcs"]:
                    raise BluetoothStateError("RFCOMM session closed with active DLCIs")
                state["history"].append(copy.deepcopy(session))
                del state["active"][session_id]
        return model._observation(event)

    def finalize(self, model: "BluetoothCoreAdapter") -> dict:
        state = _extension(model, self.pack_id)
        if state["active"]:
            raise BluetoothStateError("replay ended with active RFCOMM sessions")
        return {
            "completed_sessions": len(state["history"]),
            "data_frames": sum(record["frames"] for record in state["history"]),
        }


class AvrcpProtocolPack:
    pack_id = "public.bluetooth.avrcp.v1"
    operations = frozenset({"avrcp.command", "avrcp.response"})

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        operation = event["boundary"]["operation"]
        attributes = event["attributes"]
        model._connection(attributes)
        state = _extension(model, self.pack_id)
        transaction_id = _text(attributes, "transaction_id")
        if operation == "avrcp.command":
            if transaction_id in state["active"]:
                raise BluetoothStateError("duplicate AVRCP transaction")
            state["active"][transaction_id] = {
                "handle": _integer(attributes, "handle", maximum=0x0EFF),
                "pdu": _text(attributes, "pdu"),
                "direction": _choice(
                    attributes, "direction", {"controller-to-target", "target-to-controller"}
                ),
            }
        else:
            transaction = state["active"].get(transaction_id)
            if transaction is None or transaction["pdu"] != _text(attributes, "pdu"):
                raise BluetoothStateError("AVRCP response does not match a command")
            result = _choice(attributes, "result", {"accepted", "rejected"})
            state["history"].append({**transaction, "result": result})
            del state["active"][transaction_id]
        return model._observation(event)

    def finalize(self, model: "BluetoothCoreAdapter") -> dict:
        state = _extension(model, self.pack_id)
        if state["active"]:
            raise BluetoothStateError("replay ended with outstanding AVRCP transactions")
        return {"completed_transactions": len(state["history"])}


class HfpProtocolPack:
    pack_id = "public.bluetooth.hfp.v1"
    operations = frozenset(
        {
            "hfp.slc.open",
            "hfp.at.command",
            "hfp.at.response",
            "hfp.audio.connect",
            "hfp.audio.disconnect",
            "hfp.slc.close",
        }
    )

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        operation = event["boundary"]["operation"]
        attributes = event["attributes"]
        model._connection(attributes)
        state = _extension(model, self.pack_id)
        session_id = _session(attributes)
        if operation == "hfp.slc.open":
            if session_id in state["active"]:
                raise BluetoothStateError("duplicate HFP service-level connection")
            rfcomm_session_id = _text(attributes, "rfcomm_session_id")
            dlci = _integer(attributes, "dlci", minimum=1, maximum=63)
            rfcomm = _extension(model, RfcommProtocolPack.pack_id)["active"].get(
                rfcomm_session_id
            )
            if rfcomm is None or dlci not in rfcomm["dlcs"]:
                raise BluetoothStateError("HFP SLC requires an active RFCOMM DLCI")
            state["active"][session_id] = {
                "handle": _integer(attributes, "handle", maximum=0x0EFF),
                "role": _choice(attributes, "role", {"audio-gateway", "hands-free"}),
                "rfcomm_session_id": rfcomm_session_id,
                "dlci": dlci,
                "commands": {},
                "audio": False,
            }
        else:
            session = state["active"].get(session_id)
            if session is None:
                raise BluetoothStateError("HFP event references an unknown SLC")
            if operation == "hfp.at.command":
                command_id = _text(attributes, "command_id")
                if command_id in session["commands"]:
                    raise BluetoothStateError("duplicate HFP AT command id")
                session["commands"][command_id] = _text(attributes, "command")
            elif operation == "hfp.at.response":
                command_id = _text(attributes, "command_id")
                if command_id not in session["commands"]:
                    raise BluetoothStateError("HFP response has no pending AT command")
                _choice(attributes, "result", {"ok", "error"})
                del session["commands"][command_id]
            elif operation == "hfp.audio.connect":
                if session["audio"]:
                    raise BluetoothStateError("HFP audio is already connected")
                session["audio"] = True
            elif operation == "hfp.audio.disconnect":
                if not session["audio"]:
                    raise BluetoothStateError("HFP audio is not connected")
                session["audio"] = False
            else:
                if session["commands"] or session["audio"]:
                    raise BluetoothStateError("HFP SLC closed with active state")
                state["history"].append(copy.deepcopy(session))
                del state["active"][session_id]
        return model._observation(event)

    def finalize(self, model: "BluetoothCoreAdapter") -> dict:
        state = _extension(model, self.pack_id)
        if state["active"]:
            raise BluetoothStateError("replay ended with active HFP connections")
        return {"completed_connections": len(state["history"])}


class A2dpProtocolPack:
    pack_id = "public.bluetooth.a2dp.v1"
    operations = frozenset(
        {
            "a2dp.stream.configure",
            "a2dp.stream.open",
            "a2dp.stream.start",
            "a2dp.media",
            "a2dp.stream.suspend",
            "a2dp.stream.close",
        }
    )

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        operation = event["boundary"]["operation"]
        attributes = event["attributes"]
        model._connection(attributes)
        state = _extension(model, self.pack_id)
        stream_id = _text(attributes, "stream_id")
        if operation == "a2dp.stream.configure":
            if stream_id in state["active"]:
                raise BluetoothStateError("duplicate A2DP stream")
            state["active"][stream_id] = {
                "handle": _integer(attributes, "handle", maximum=0x0EFF),
                "codec": _text(attributes, "codec"),
                "state": "configured",
                "last_sequence": -1,
                "media_packets": 0,
            }
        else:
            stream = state["active"].get(stream_id)
            if stream is None:
                raise BluetoothStateError("A2DP event references an unknown stream")
            transitions = {
                "a2dp.stream.open": ("configured", "open"),
                "a2dp.stream.start": ("open", "streaming"),
                "a2dp.stream.suspend": ("streaming", "open"),
            }
            if operation in transitions:
                expected, next_state = transitions[operation]
                if stream["state"] != expected:
                    raise BluetoothStateError(f"invalid A2DP transition from {stream['state']}")
                stream["state"] = next_state
            elif operation == "a2dp.media":
                if stream["state"] != "streaming":
                    raise BluetoothStateError("A2DP media arrived while stream was not running")
                sequence = _integer(attributes, "sequence", maximum=0xFFFF)
                if sequence <= stream["last_sequence"]:
                    raise BluetoothStateError("A2DP media sequence did not increase")
                _integer(attributes, "length", minimum=1, maximum=65535)
                stream["last_sequence"] = sequence
                stream["media_packets"] += 1
            else:
                if stream["state"] != "open":
                    raise BluetoothStateError("A2DP stream closed from an invalid state")
                state["history"].append(copy.deepcopy(stream))
                del state["active"][stream_id]
        return model._observation(event)

    def finalize(self, model: "BluetoothCoreAdapter") -> dict:
        state = _extension(model, self.pack_id)
        if state["active"]:
            raise BluetoothStateError("replay ended with active A2DP streams")
        return {
            "completed_streams": len(state["history"]),
            "media_packets": sum(record["media_packets"] for record in state["history"]),
        }


class LeAudioProtocolPack:
    pack_id = "public.bluetooth.le-audio.v1"
    operations = frozenset(
        {
            "le_audio.group.configure",
            "le_audio.cis.establish",
            "le_audio.stream.start",
            "le_audio.iso.data",
            "le_audio.stream.stop",
            "le_audio.cis.disconnect",
            "le_audio.group.release",
        }
    )

    def apply(self, model: "BluetoothCoreAdapter", event: dict) -> dict:
        operation = event["boundary"]["operation"]
        attributes = event["attributes"]
        state = _extension(model, self.pack_id)
        group_id = _text(attributes, "group_id")
        if operation == "le_audio.group.configure":
            if group_id in state["active"]:
                raise BluetoothStateError("duplicate LE Audio group")
            state["active"][group_id] = {
                "codec": _text(attributes, "codec"),
                "streams": {},
                "iso_packets": 0,
            }
        else:
            group = state["active"].get(group_id)
            if group is None:
                raise BluetoothStateError("LE Audio event references an unknown group")
            if operation == "le_audio.group.release":
                if group["streams"]:
                    raise BluetoothStateError("LE Audio group released with active streams")
                state["history"].append(copy.deepcopy(group))
                del state["active"][group_id]
                return model._observation(event)
            stream_id = _text(attributes, "stream_id")
            if operation == "le_audio.cis.establish":
                model._connection(attributes)
                if stream_id in group["streams"]:
                    raise BluetoothStateError("duplicate LE Audio CIS")
                group["streams"][stream_id] = {
                    "handle": _integer(attributes, "handle", maximum=0x0EFF),
                    "state": "established",
                    "last_sequence": -1,
                }
            else:
                stream = group["streams"].get(stream_id)
                if stream is None:
                    raise BluetoothStateError("LE Audio event references an unknown CIS")
                if operation == "le_audio.stream.start":
                    if stream["state"] != "established":
                        raise BluetoothStateError("LE Audio stream start from invalid state")
                    stream["state"] = "streaming"
                elif operation == "le_audio.iso.data":
                    if stream["state"] != "streaming":
                        raise BluetoothStateError("LE Audio ISO data arrived before stream start")
                    sequence = _integer(attributes, "sequence", maximum=0xFFFF)
                    if sequence <= stream["last_sequence"]:
                        raise BluetoothStateError("LE Audio ISO sequence did not increase")
                    _integer(attributes, "length", minimum=1, maximum=65535)
                    stream["last_sequence"] = sequence
                    group["iso_packets"] += 1
                elif operation == "le_audio.stream.stop":
                    if stream["state"] != "streaming":
                        raise BluetoothStateError("LE Audio stream stop from invalid state")
                    stream["state"] = "established"
                else:
                    if stream["state"] != "established":
                        raise BluetoothStateError("LE Audio CIS disconnected while streaming")
                    del group["streams"][stream_id]
        return model._observation(event)

    def finalize(self, model: "BluetoothCoreAdapter") -> dict:
        state = _extension(model, self.pack_id)
        if state["active"]:
            raise BluetoothStateError("replay ended with active LE Audio groups")
        return {
            "completed_groups": len(state["history"]),
            "iso_packets": sum(record["iso_packets"] for record in state["history"]),
        }
