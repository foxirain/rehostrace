"""Source-free ARM64 lifetime-point and precedence-edge discovery.

The implementation intentionally reads only ELF metadata, executable bytes,
symbols, and relocations.  DWARF and source paths are never consulted.  It is
small enough to ship in the public artifact and deterministic enough for its
output to be bound into an evidence receipt.
"""

from __future__ import annotations

import copy
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

from .model import CausalTrace, ID_RE, SHA256_RE, canonical_sha256


SHT_SYMTAB = 2
SHT_RELA = 4
SHF_EXECINSTR = 0x4
STT_FUNC = 2
R_AARCH64_JUMP26 = 282
R_AARCH64_CALL26 = 283


def _digest(document: dict) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _binding_digest(binding: dict) -> str:
    normalized = copy.deepcopy(binding)
    if isinstance(normalized.get("actions"), list):
        normalized["actions"] = sorted(normalized["actions"], key=lambda item: item["id"])
    return _digest(normalized)


def _cstring(blob: bytes, offset: int) -> str:
    end = blob.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated ELF string")
    return blob[offset:end].decode("utf-8", errors="strict")


def _signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    sh_type: int
    flags: int
    offset: int
    size: int
    link: int
    info: int
    entsize: int


@dataclass(frozen=True)
class Symbol:
    index: int
    name: str
    value: int
    size: int
    info: int
    shndx: int

    @property
    def kind(self) -> int:
        return self.info & 0xF


@dataclass(frozen=True)
class Relocation:
    source_section: int
    offset: int
    kind: int
    symbol_index: int


class Arm64Relocatable:
    """Minimal dependency-free ELF64/AArch64 relocatable reader."""

    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if len(self.data) < 64 or self.data[:4] != b"\x7fELF":
            raise ValueError("input is not an ELF file")
        if self.data[4] != 2 or self.data[5] != 1:
            raise ValueError("only little-endian ELF64 is supported")
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", self.data, 0)
        if header[2] != 183:
            raise ValueError("only AArch64 ELF is supported")
        if header[1] != 1:
            raise ValueError("lifetime discovery requires an ET_REL kernel module")
        shoff, shentsize, shnum, shstrndx = header[6], header[11], header[12], header[13]
        if shentsize != 64 or shoff + shentsize * shnum > len(self.data):
            raise ValueError("invalid ELF section table")
        raw_sections = [
            struct.unpack_from("<IIQQQQIIQQ", self.data, shoff + index * shentsize)
            for index in range(shnum)
        ]
        if shstrndx >= shnum:
            raise ValueError("invalid ELF section-name table")
        names_record = raw_sections[shstrndx]
        names = self.data[names_record[4] : names_record[4] + names_record[5]]
        self.sections: list[Section] = []
        for index, record in enumerate(raw_sections):
            name = _cstring(names, record[0]) if record[0] < len(names) else ""
            section = Section(
                index=index,
                name=name,
                sh_type=record[1],
                flags=record[2],
                offset=record[4],
                size=record[5],
                link=record[6],
                info=record[7],
                entsize=record[9],
            )
            if section.offset + section.size > len(self.data) and section.sh_type != 8:
                raise ValueError(f"section outside ELF: {section.name}")
            self.sections.append(section)

        self.symbols: list[Symbol] = []
        self._parse_symbols()
        self.relocations: list[Relocation] = []
        self._parse_relocations()
        raw_functions = [
            symbol for symbol in self.symbols if symbol.kind == STT_FUNC and symbol.size
        ]
        aliases: dict[tuple[int, int, int], list[Symbol]] = {}
        for symbol in raw_functions:
            aliases.setdefault((symbol.shndx, symbol.value, symbol.size), []).append(symbol)
        self._canonical_function = {
            key: min(records, key=lambda item: (len(item.name), item.name))
            for key, records in aliases.items()
        }
        self.functions = sorted(
            self._canonical_function.values(), key=lambda item: (item.shndx, item.value, item.name)
        )
        self.functions_by_name = {symbol.name: symbol for symbol in self.functions}

    def _parse_symbols(self) -> None:
        symtabs = [section for section in self.sections if section.sh_type == SHT_SYMTAB]
        if len(symtabs) != 1:
            raise ValueError("exactly one ELF symbol table is required")
        table = symtabs[0]
        if table.entsize != 24 or table.link >= len(self.sections):
            raise ValueError("invalid ELF symbol table")
        strings_section = self.sections[table.link]
        strings = self.data[
            strings_section.offset : strings_section.offset + strings_section.size
        ]
        for index, position in enumerate(range(table.offset, table.offset + table.size, 24)):
            name_offset, info, _other, shndx, value, size = struct.unpack_from(
                "<IBBHQQ", self.data, position
            )
            name = _cstring(strings, name_offset) if name_offset < len(strings) else ""
            self.symbols.append(Symbol(index, name, value, size, info, shndx))

    def _parse_relocations(self) -> None:
        for section in self.sections:
            if section.sh_type != SHT_RELA:
                continue
            if section.entsize != 24 or section.info >= len(self.sections):
                raise ValueError(f"invalid relocation section: {section.name}")
            for position in range(section.offset, section.offset + section.size, 24):
                offset, info, _addend = struct.unpack_from("<QQq", self.data, position)
                symbol_index = info >> 32
                if symbol_index >= len(self.symbols):
                    raise ValueError(f"relocation has invalid symbol index: {section.name}")
                self.relocations.append(
                    Relocation(section.info, offset, info & 0xFFFFFFFF, symbol_index)
                )

    def containing_function(self, section_index: int, offset: int) -> Symbol | None:
        matches = [
            function
            for function in self.functions
            if function.shndx == section_index
            and function.value <= offset < function.value + function.size
        ]
        return max(matches, key=lambda item: item.value) if matches else None

    def calls(self) -> list[dict]:
        records = []
        for relocation in self.relocations:
            if relocation.kind not in {R_AARCH64_CALL26, R_AARCH64_JUMP26}:
                continue
            source = self.containing_function(relocation.source_section, relocation.offset)
            if source is None:
                continue
            target = self.symbols[relocation.symbol_index]
            if target.kind == STT_FUNC and target.size:
                target = self._canonical_function.get(
                    (target.shndx, target.value, target.size), target
                )
            records.append(
                {
                    "source": source.name,
                    "target": target.name,
                    "offset": relocation.offset,
                    "kind": "call" if relocation.kind == R_AARCH64_CALL26 else "tail-jump",
                    "target_defined": target.shndx != 0,
                }
            )
        return sorted(records, key=lambda item: (item["source"], item["offset"], item["target"]))

    def data_function_references(self) -> list[str]:
        references = set()
        for relocation in self.relocations:
            source_section = self.sections[relocation.source_section]
            target = self.symbols[relocation.symbol_index]
            if not (source_section.flags & SHF_EXECINSTR) and target.kind == STT_FUNC:
                if target.size:
                    target = self._canonical_function.get(
                        (target.shndx, target.value, target.size), target
                    )
                references.add(target.name)
        return sorted(references)

    @staticmethod
    def _branch(instruction: int, address: int) -> tuple[str, int | None]:
        opcode6 = instruction >> 26
        if opcode6 == 0b000101:
            return "jump", address + (_signed(instruction & 0x03FFFFFF, 26) << 2)
        if opcode6 == 0b100101:
            return "call", None
        if instruction & 0xFF000010 == 0x54000000:
            return "conditional", address + (_signed((instruction >> 5) & 0x7FFFF, 19) << 2)
        if instruction & 0x7E000000 == 0x34000000:
            return "conditional", address + (_signed((instruction >> 5) & 0x7FFFF, 19) << 2)
        if instruction & 0x7E000000 == 0x36000000:
            return "conditional", address + (_signed((instruction >> 5) & 0x3FFF, 14) << 2)
        if instruction & 0xFFFFFC1F in {0xD65F0000, 0xD61F0000}:
            return "terminal", None
        return "linear", None

    def function_cfg(self, function: Symbol) -> dict:
        section = self.sections[function.shndx]
        start = section.offset + function.value
        code = self.data[start : start + function.size]
        instruction_count = len(code) // 4
        leaders = {function.value}
        branches: dict[int, tuple[str, int | None]] = {}
        for index in range(instruction_count):
            address = function.value + index * 4
            instruction = struct.unpack_from("<I", code, index * 4)[0]
            kind, target = self._branch(instruction, address)
            branches[address] = (kind, target)
            if target is not None and function.value <= target < function.value + function.size:
                leaders.add(target)
            if kind in {"conditional", "jump", "terminal"}:
                fallthrough = address + 4
                if fallthrough < function.value + function.size:
                    leaders.add(fallthrough)
        ordered = sorted(leaders)
        edges: set[tuple[int, int]] = set()
        for index, leader in enumerate(ordered):
            end = (ordered[index + 1] if index + 1 < len(ordered) else function.value + function.size)
            last = end - 4
            kind, target = branches.get(last, ("linear", None))
            if target is not None and target in leaders:
                edges.add((leader, target))
            if kind not in {"jump", "terminal"} and end < function.value + function.size:
                edges.add((leader, end))
        return {
            "function": function.name,
            "size": function.size,
            "instruction_count": instruction_count,
            "basic_block_count": len(ordered),
            "cfg_edge_count": len(edges),
        }


def validate_discovery_policy(policy: dict) -> dict:
    if not isinstance(policy, dict) or policy.get("schema_version") != "rehostrace.discovery-policy/v1":
        raise ValueError("invalid discovery policy schema_version")
    policy_id = policy.get("policy_id")
    if not isinstance(policy_id, str) or not ID_RE.fullmatch(policy_id):
        raise ValueError("invalid discovery policy_id")
    primitives = policy.get("primitives")
    if not isinstance(primitives, dict):
        raise ValueError("discovery policy primitives are required")
    for field in ("free_sinks", "lock_acquire", "lock_release"):
        values = primitives.get(field)
        if not isinstance(values, list) or not values or len(values) != len(set(values)):
            raise ValueError(f"policy {field} must be a non-empty unique list")
        if any(not isinstance(value, str) or not value for value in values):
            raise ValueError(f"policy {field} contains an invalid symbol")
    maximum = policy.get("passive_leaf_max_bytes")
    if type(maximum) is not int or not 4 <= maximum <= 256:
        raise ValueError("passive_leaf_max_bytes must be in [4, 256]")
    minimum = policy.get("minimum_competing_actions")
    if type(minimum) is not int or minimum < 2:
        raise ValueError("minimum_competing_actions must be at least two")
    return {"status": "passed", "policy_id": policy_id, "policy_sha256": _digest(policy)}


def _reachable(start: str, graph: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    pending = [start]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pending.extend(sorted(graph.get(current, set()) - seen, reverse=True))
    return seen


def _nearest_sync(calls: list[dict], index: int, names: set[str], step: int) -> str | None:
    position = index + step
    while 0 <= position < len(calls):
        target = calls[position]["target"]
        if target in names:
            return target
        position += step
    return None


def _concurrent_boundary(binding: dict, trace: CausalTrace) -> tuple[list[dict], list[list[str]]]:
    if binding.get("schema_version") != "rehostrace.binding/v1":
        raise ValueError("invalid binding schema_version")
    if binding.get("trace_sha256") != trace.digest:
        raise ValueError("binding trace_sha256 does not match trace")
    actions = binding.get("actions")
    if not isinstance(actions, list) or not actions:
        raise ValueError("binding actions are required")
    groups: dict[str, list[dict]] = {}
    for action in actions:
        if not isinstance(action, dict) or action.get("event_id") not in trace.events:
            raise ValueError("binding action references an unknown event")
        groups.setdefault(action.get("launch_group"), []).append(action)
    pairs = []
    for group, members in sorted(groups.items()):
        if not isinstance(group, str):
            raise ValueError("binding launch_group is invalid")
        for first_index, first in enumerate(members):
            for second in members[first_index + 1 :]:
                if trace.concurrent(first["event_id"], second["event_id"]):
                    pairs.append(sorted([first["id"], second["id"]]))
    return actions, sorted(pairs)


def discover_lifetime_candidates(
    module_path: Path, trace_document: dict, binding: dict, policy: dict
) -> dict:
    """Discover lifetime paths, passive points, and precedence candidates.

    The policy names only generic synchronization/allocation primitives.  It
    cannot name target functions, marker functions, offsets, points, or edges.
    """

    policy_validation = validate_discovery_policy(policy)
    forbidden = {
        "target_functions",
        "marker_functions",
        "candidate_points",
        "candidate_edges",
        "boundary_entrypoints",
    }
    overlap = forbidden & set(policy)
    if overlap:
        raise ValueError(f"policy contains researcher-supplied target hints: {sorted(overlap)}")
    trace = CausalTrace(trace_document)
    actions, concurrent_pairs = _concurrent_boundary(binding, trace)
    minimum = policy["minimum_competing_actions"]
    if len(actions) < minimum or not concurrent_pairs:
        raise ValueError("boundary projection has no qualifying concurrent action pair")

    image = Arm64Relocatable(module_path)
    calls = image.calls()
    graph: dict[str, set[str]] = {}
    calls_by_source: dict[str, list[dict]] = {}
    for call in calls:
        calls_by_source.setdefault(call["source"], []).append(call)
        if call["target_defined"]:
            graph.setdefault(call["source"], set()).add(call["target"])
    for records in calls_by_source.values():
        records.sort(key=lambda item: item["offset"])

    free_sinks = set(policy["primitives"]["free_sinks"])
    direct_sink_paths = sorted(
        source
        for source, records in calls_by_source.items()
        if any(record["target"] in free_sinks for record in records)
        and image.functions_by_name[source].shndx < len(image.sections)
        and image.sections[image.functions_by_name[source].shndx].name == ".text"
    )
    if len(direct_sink_paths) < minimum:
        raise ValueError("fewer than two runtime text paths reach a configured free sink")

    data_roots = image.data_function_references()
    dispatch_candidates = []
    for root in data_roots:
        reached = _reachable(root, graph)
        sink_paths = sorted(set(direct_sink_paths) & reached)
        if len(sink_paths) >= minimum:
            dispatch_candidates.append({"root": root, "sink_paths": sink_paths})
    if not dispatch_candidates:
        raise ValueError("no data-referenced dispatcher reaches competing free paths")
    dispatch_candidates.sort(key=lambda item: (len(item["sink_paths"]), item["root"]))
    selected = dispatch_candidates[0]
    dispatcher = selected["root"]
    # Peel compiler-generated one-edge jump veneers without relying on names.
    while True:
        local = sorted(graph.get(dispatcher, set()))
        qualifying = [
            target
            for target in local
            if len(set(direct_sink_paths) & _reachable(target, graph)) >= minimum
        ]
        if len(qualifying) != 1:
            break
        dispatcher = qualifying[0]

    hazard_paths = sorted(set(direct_sink_paths) & _reachable(dispatcher, graph))
    passive_max = policy["passive_leaf_max_bytes"]
    passive = {
        function.name
        for function in image.functions
        if image.sections[function.shndx].name == ".text"
        and function.size <= passive_max
        and not calls_by_source.get(function.name)
    }
    acquire = set(policy["primitives"]["lock_acquire"])
    release = set(policy["primitives"]["lock_release"])
    sync = acquire | release
    post_release = []
    pre_acquire = []
    observation_candidates = []
    lifetime_paths = []
    for path in hazard_paths:
        records = calls_by_source[path]
        sinks = [record for record in records if record["target"] in free_sinks]
        lifetime_paths.append(
            {
                "function": path,
                "free_callsites": [
                    {"sink": record["target"], "offset": record["offset"]} for record in sinks
                ],
                "ordered_calls": [
                    {"target": record["target"], "offset": record["offset"]}
                    for record in records
                ],
            }
        )
        for index, record in enumerate(records):
            if record["target"] not in passive:
                continue
            previous = _nearest_sync(records, index, sync, -1)
            following = _nearest_sync(records, index, sync, 1)
            if previous in release and following in acquire:
                post_release.append(
                    {
                        "path": path,
                        "symbol": record["target"],
                        "callsite_offset": record["offset"],
                        "previous_sync": previous,
                        "following_sync": following,
                    }
                )
            if previous in acquire and following in acquire:
                pre_acquire.append(
                    {
                        "path": path,
                        "symbol": record["target"],
                        "callsite_offset": record["offset"],
                        "previous_sync": previous,
                        "following_sync": following,
                    }
                )
            next_target = records[index + 1]["target"] if index + 1 < len(records) else None
            observation_role = None
            if next_target in free_sinks:
                observation_role = "pre-free"
            elif previous in acquire and following in release:
                observation_role = "inside-lock-region"
            elif previous in release and following in release:
                observation_role = "post-release-object-held"
            if observation_role:
                observation_candidates.append(
                    {
                        "role": observation_role,
                        "path": path,
                        "symbol": record["target"],
                        "callsite_offset": record["offset"],
                        "previous_sync": previous,
                        "following_sync": following,
                        "next_call": next_target,
                    }
                )

    post_release.sort(key=lambda item: (item["path"], item["callsite_offset"]))
    pre_acquire.sort(key=lambda item: (item["path"], item["callsite_offset"]))
    points = []
    post_ids = {}
    pre_ids = {}
    for index, point in enumerate(post_release):
        point_id = f"auto.post-release-handoff.{index}"
        post_ids[(point["path"], point["symbol"], point["callsite_offset"])] = point_id
        points.append(
            {
                "id": point_id,
                "role": "post-release-handoff",
                "selector": {"kind": "symbol", "symbol": point["symbol"]},
                "path": point["path"],
                "callsite_offset": point["callsite_offset"],
                "evidence": {
                    "previous_sync": point["previous_sync"],
                    "following_sync": point["following_sync"],
                },
            }
        )
    for index, point in enumerate(pre_acquire):
        point_id = f"auto.pre-acquire-under-lock.{index}"
        pre_ids[(point["path"], point["symbol"], point["callsite_offset"])] = point_id
        points.append(
            {
                "id": point_id,
                "role": "pre-acquire-under-lock",
                "selector": {"kind": "symbol", "symbol": point["symbol"]},
                "path": point["path"],
                "callsite_offset": point["callsite_offset"],
                "evidence": {
                    "previous_sync": point["previous_sync"],
                    "following_sync": point["following_sync"],
                },
            }
        )

    edges = []
    for pre in pre_acquire:
        for post in post_release:
            if pre["path"] == post["path"]:
                continue
            from_id = pre_ids[(pre["path"], pre["symbol"], pre["callsite_offset"])]
            to_id = post_ids[(post["path"], post["symbol"], post["callsite_offset"])]
            edges.append(
                {
                    "id": f"edge.{len(edges)}",
                    "from_point": from_id,
                    "to_point": to_id,
                    "relation": "from-enter-before-to-release",
                    "schedule_fragment": {
                        "signal": f"{from_id}.entered",
                        "milestone": {"point": from_id, "phase": "enter"},
                        "gate": {
                            "after_signal": f"{from_id}.entered",
                            "before_release_of": to_id,
                        },
                    },
                    "derivation": "cross-path lock-handoff inversion with a shared free sink",
                }
            )

    if not points or not edges:
        raise ValueError("binary structure did not yield candidate lifetime points and edges")

    grouped_observations: dict[tuple[str, str], list[dict]] = {}
    for record in observation_candidates:
        grouped_observations.setdefault((record["role"], record["symbol"]), []).append(record)
    observation_points = []
    for index, ((role, symbol), records) in enumerate(sorted(grouped_observations.items())):
        observation_points.append(
            {
                "id": f"auto.observation.{role}.{index}",
                "role": role,
                "selector": {"kind": "symbol", "symbol": symbol},
                "paths": sorted({record["path"] for record in records}),
                "callsites": sorted(record["callsite_offset"] for record in records),
                "evidence": [
                    {
                        key: record[key]
                        for key in (
                            "path",
                            "callsite_offset",
                            "previous_sync",
                            "following_sync",
                            "next_call",
                        )
                    }
                    for record in sorted(records, key=lambda item: (item["path"], item["callsite_offset"]))
                ],
            }
        )

    cfg_records = [
        image.function_cfg(function)
        for function in image.functions
        if image.sections[function.shndx].flags & SHF_EXECINSTR
    ]
    result = {
        "schema_version": "rehostrace.lifetime-discovery/v1",
        "discovery_id": f"discovery.{hashlib.sha256(module_path.read_bytes()).hexdigest()[:16]}",
        "inputs": {
            "module_sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
            "trace_sha256": trace.digest,
            "binding_sha256": _binding_digest(binding),
            "policy_sha256": policy_validation["policy_sha256"],
        },
        "analysis_contract": {
            "architecture": "arm64",
            "binary_kind": "elf64-et-rel",
            "source_used": False,
            "debug_information_used": False,
            "target_function_hints_used": False,
            "target_point_hints_used": False,
            "target_edge_hints_used": False,
            "inputs_used": ["elf-symbols", "elf-relocations", "executable-bytes", "causal-trace", "boundary-binding", "generic-primitive-policy"],
        },
        "binary_cfg": {
            "function_count": len(cfg_records),
            "basic_block_count": sum(record["basic_block_count"] for record in cfg_records),
            "cfg_edge_count": sum(record["cfg_edge_count"] for record in cfg_records),
            "call_edge_count": len(calls),
            "functions": cfg_records,
        },
        "boundary": {
            "action_count": len(actions),
            "concurrent_action_pairs": concurrent_pairs,
            "data_referenced_roots": data_roots,
            "selected_dispatcher": dispatcher,
        },
        "lifetime_paths": lifetime_paths,
        "discovered_points": sorted(points, key=lambda item: item["id"]),
        "observation_points": observation_points,
        "candidate_precedence_edges": edges,
        "claim_boundary": "Candidates are source-free structural hypotheses from one public binary and causal boundary projection. They require dynamic search/oracle validation and do not establish a proprietary target, stock consequence, or exploitability.",
    }
    result["integrity"] = {"canonical_sha256": _digest(result)}
    return result


def materialize_discovered_experiment(result: dict, trace_document: dict, binding: dict) -> dict:
    """Compile one discovered edge into schedule, binding, and oracle documents.

    This consumes discovery output only.  It does not accept a point list, an
    edge list, or a reference schedule as an argument.
    """

    validate_discovery_result(result)
    trace = CausalTrace(trace_document)
    if binding.get("trace_sha256") != trace.digest:
        raise ValueError("binding trace_sha256 does not match trace")
    edges = result["candidate_precedence_edges"]
    if len(edges) != 1:
        raise ValueError("automatic experiment materialization currently requires one edge")
    points_by_id = {point["id"]: point for point in result["discovered_points"]}
    edge = edges[0]
    source = points_by_id[edge["from_point"]]
    target = points_by_id[edge["to_point"]]
    observations = result.get("observation_points", [])
    by_role: dict[str, list[dict]] = {}
    for point in observations:
        by_role.setdefault(point["role"], []).append(point)
    required_roles = {"inside-lock-region", "post-release-object-held", "pre-free"}
    if set(by_role) != required_roles or any(
        len(by_role[role]) != 1 for role in required_roles
    ):
        raise ValueError("discovery did not produce one point for every dynamic oracle role")

    target_enter = f"{target['id']}.entered"
    source_enter = f"{source['id']}.entered"
    target_release = f"{target['id']}.released"
    observation_signals = {
        role: f"{by_role[role][0]['id']}.entered"
        for role in ("inside-lock-region", "post-release-object-held")
    }
    second_free = "auto.second-free"
    signals = [
        target_enter,
        source_enter,
        target_release,
        observation_signals["post-release-object-held"],
        observation_signals["inside-lock-region"],
        second_free,
    ]
    schedule_points = [
        {
            "id": target["id"],
            "selector": copy.deepcopy(target["selector"]),
            "description": "Automatically recovered post-release handoff point",
        },
        {
            "id": source["id"],
            "selector": copy.deepcopy(source["selector"]),
            "description": "Automatically recovered pre-acquire-under-lock point",
        },
        *[
            {
                "id": by_role[role][0]["id"],
                "selector": copy.deepcopy(by_role[role][0]["selector"]),
                "description": f"Automatically recovered {role} observation point",
            }
            for role in ("post-release-object-held", "inside-lock-region", "pre-free")
        ],
    ]
    milestones = [
        {"signal": target_enter, "point": target["id"], "phase": "enter"},
        {"signal": source_enter, "point": source["id"], "phase": "enter"},
        {"signal": target_release, "point": target["id"], "phase": "release"},
        {
            "signal": observation_signals["post-release-object-held"],
            "point": by_role["post-release-object-held"][0]["id"],
            "phase": "enter",
        },
        {
            "signal": observation_signals["inside-lock-region"],
            "point": by_role["inside-lock-region"][0]["id"],
            "phase": "enter",
        },
    ]
    prefix = result["integrity"]["canonical_sha256"][:16]
    constraints = {
        "schema_version": "rehostrace.schedule-constraints/v1",
        "synthesis_id": f"auto.discovery.{prefix}.constraints",
        "schedule_id": f"auto.discovery.{prefix}.schedule",
        "disclosure": "public-synthetic",
        "timeout_ms": 5000,
        "signal_order": signals,
        "identity": {"capture": "arg0", "policy": "same-across-points"},
        "points": schedule_points,
        "milestones": milestones,
        "gates": [
            {"after_signal": source_enter, "before_release_of": target["id"]}
        ],
        "counters": [
            {
                "id": "auto.free-entries",
                "point": by_role["pre-free"][0]["id"],
                "threshold": 2,
                "emit_at_threshold": second_free,
            }
        ],
        "claim_boundary": "Generated exclusively from a source-free discovery result; dynamic validation remains required and no product claim transfers.",
    }
    from .synthesis import synthesize_schedule

    schedule, synthesis = synthesize_schedule(constraints)
    generated_binding = copy.deepcopy(binding)
    generated_binding["binding_id"] = f"auto.discovery.{prefix}.binding"
    generated_binding["schedule_sha256"] = synthesis["schedule_sha256"]
    delayed = [action for action in generated_binding["actions"] if "start_after_signal" in action]
    if len(delayed) > 1:
        raise ValueError("materialization supports at most one delayed competing action")
    for action in generated_binding["actions"]:
        action.pop("start_after_signal", None)
    if delayed:
        delayed_id = delayed[0]["id"]
        next(action for action in generated_binding["actions"] if action["id"] == delayed_id)[
            "start_after_signal"
        ] = target_enter

    post_path = target["path"]
    oracle = {
        "schema_version": "rehostrace.oracle/v1",
        "oracle_id": f"auto.discovery.{prefix}.oracle",
        "identity": {
            "capture": "object",
            "relation": "equal",
            "points": [point["id"] for point in schedule_points],
        },
        "required_points": [
            {
                "id": point["id"],
                "min_hits": 2 if point["id"] == by_role["pre-free"][0]["id"] else 1,
                "max_hits": 2 if point["id"] == by_role["pre-free"][0]["id"] else 1,
            }
            for point in schedule_points
        ],
        "counters": [{"id": "auto.free-entries", "minimum": 2, "maximum": 2}],
        "forbidden_events": ["gate.timeout", "object.mismatch"],
        "sanitizer": {
            "required": True,
            "kinds": ["double-free", "invalid-free"],
            "required_frames": [post_path, result["boundary"]["selected_dispatcher"]],
        },
        "claim_boundary": "A positive result validates only the automatically materialized public-fixture schedule and oracle.",
    }
    return {
        "constraints": constraints,
        "schedule": schedule,
        "binding": generated_binding,
        "oracle": oracle,
        "synthesis": synthesis,
    }


def validate_discovery_result(result: dict) -> dict:
    if not isinstance(result, dict) or result.get("schema_version") != "rehostrace.lifetime-discovery/v1":
        raise ValueError("invalid lifetime-discovery schema_version")
    integrity = result.get("integrity")
    unsigned = copy.deepcopy(result)
    unsigned.pop("integrity", None)
    expected = _digest(unsigned)
    if not isinstance(integrity, dict) or integrity.get("canonical_sha256") != expected:
        raise ValueError("lifetime-discovery integrity mismatch")
    inputs = result.get("inputs")
    if not isinstance(inputs, dict) or any(
        not isinstance(inputs.get(field), str) or not SHA256_RE.fullmatch(inputs[field])
        for field in ("module_sha256", "trace_sha256", "binding_sha256", "policy_sha256")
    ):
        raise ValueError("lifetime-discovery input identities are invalid")
    contract = result.get("analysis_contract")
    if not isinstance(contract, dict) or any(
        contract.get(field) is not False
        for field in (
            "source_used",
            "debug_information_used",
            "target_function_hints_used",
            "target_point_hints_used",
            "target_edge_hints_used",
        )
    ):
        raise ValueError("lifetime-discovery contract permits target/source hints")
    points = result.get("discovered_points")
    observations = result.get("observation_points")
    edges = result.get("candidate_precedence_edges")
    if (
        not isinstance(points, list)
        or not points
        or not isinstance(observations, list)
        or not observations
        or not isinstance(edges, list)
        or not edges
    ):
        raise ValueError("lifetime-discovery must emit points and edges")
    point_ids = {point.get("id") for point in points if isinstance(point, dict)}
    if len(point_ids) != len(points) or any(
        not isinstance(point_id, str) or not ID_RE.fullmatch(point_id) for point_id in point_ids
    ):
        raise ValueError("discovered point ids are invalid")
    for edge in edges:
        if edge.get("from_point") not in point_ids or edge.get("to_point") not in point_ids:
            raise ValueError("candidate edge references an unknown point")
    return {
        "status": "passed",
        "discovery_id": result.get("discovery_id"),
        "point_count": len(points),
        "edge_count": len(edges),
        "canonical_sha256": expected,
    }
