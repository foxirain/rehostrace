import copy
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

import rehostrace.discovery as discovery_module
from rehostrace import (
    Arm64Relocatable,
    discover_lifetime_candidates,
    materialize_discovered_experiment,
    validate_discovery_policy,
    validate_discovery_result,
)


def build_arm64_relocatable(path):
    """Build a tiny transparent ELF64/AArch64 call-graph fixture in memory."""

    functions = {
        "dispatch": (0, 8),
        "path_a": (16, 32),
        "path_b": (64, 28),
        "marker_post": (96, 4),
        "marker_pre": (100, 4),
        "marker_held": (104, 4),
        "marker_inside": (108, 4),
        "marker_free": (112, 4),
    }
    external = ("mutex_lock", "mutex_unlock", "kfree")
    names = [*functions, *external]
    string_table = bytearray(b"\0")
    string_offsets = {}
    for name in names:
        string_offsets[name] = len(string_table)
        string_table.extend(name.encode() + b"\0")

    symbols = [b"\0" * 24]
    symbol_indexes = {}
    for name, (value, size) in functions.items():
        symbol_indexes[name] = len(symbols)
        symbols.append(
            struct.pack("<IBBHQQ", string_offsets[name], 0x12, 0, 1, value, size)
        )
    for name in external:
        symbol_indexes[name] = len(symbols)
        symbols.append(struct.pack("<IBBHQQ", string_offsets[name], 0x12, 0, 0, 0, 0))
    symbol_table = b"".join(symbols)

    calls = [
        (0, "path_a"),
        (4, "path_b"),
        (16, "mutex_unlock"),
        (20, "marker_post"),
        (24, "mutex_lock"),
        (28, "mutex_unlock"),
        (32, "marker_held"),
        (36, "mutex_unlock"),
        (40, "marker_free"),
        (44, "kfree"),
        (64, "mutex_lock"),
        (68, "marker_pre"),
        (72, "mutex_lock"),
        (76, "marker_inside"),
        (80, "mutex_unlock"),
        (84, "marker_free"),
        (88, "kfree"),
    ]
    text = bytearray(struct.pack("<I", 0xD503201F) * 29)
    for offset, _target in calls:
        struct.pack_into("<I", text, offset, 0x94000000)
    for name in ("marker_post", "marker_pre", "marker_held", "marker_inside", "marker_free"):
        struct.pack_into("<I", text, functions[name][0], 0xD65F03C0)
    rela_text = b"".join(
        struct.pack(
            "<QQq",
            offset,
            (symbol_indexes[target] << 32) | discovery_module.R_AARCH64_CALL26,
            0,
        )
        for offset, target in calls
    )
    data = b"\0" * 8
    rela_data = struct.pack(
        "<QQq", 0, (symbol_indexes["dispatch"] << 32) | 257, 0
    )

    section_names = (
        b"\0.text\0.data\0.rela.text\0.rela.data\0.symtab\0.strtab\0.shstrtab\0"
    )
    section_name_offset = {
        name: section_names.index(name.encode())
        for name in (
            ".text",
            ".data",
            ".rela.text",
            ".rela.data",
            ".symtab",
            ".strtab",
            ".shstrtab",
        )
    }

    image = bytearray(64)

    def append_section(payload, alignment):
        while len(image) % alignment:
            image.append(0)
        offset = len(image)
        image.extend(payload)
        return offset

    offsets = {
        ".text": append_section(text, 16),
        ".data": append_section(data, 8),
        ".rela.text": append_section(rela_text, 8),
        ".rela.data": append_section(rela_data, 8),
        ".symtab": append_section(symbol_table, 8),
        ".strtab": append_section(string_table, 1),
        ".shstrtab": append_section(section_names, 1),
    }
    while len(image) % 8:
        image.append(0)
    section_header_offset = len(image)

    def section_header(name, kind, flags, size, link=0, info=0, align=1, entsize=0):
        return struct.pack(
            "<IIQQQQIIQQ",
            section_name_offset[name],
            kind,
            flags,
            0,
            offsets[name],
            size,
            link,
            info,
            align,
            entsize,
        )

    image.extend(b"\0" * 64)
    image.extend(section_header(".text", 1, 0x6, len(text), align=4))
    image.extend(section_header(".data", 1, 0x3, len(data), align=8))
    image.extend(
        section_header(".rela.text", 4, 0, len(rela_text), link=5, info=1, align=8, entsize=24)
    )
    image.extend(
        section_header(".rela.data", 4, 0, len(rela_data), link=5, info=2, align=8, entsize=24)
    )
    image.extend(
        section_header(".symtab", 2, 0, len(symbol_table), link=6, info=1, align=8, entsize=24)
    )
    image.extend(section_header(".strtab", 3, 0, len(string_table)))
    image.extend(section_header(".shstrtab", 3, 0, len(section_names)))

    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        image,
        0,
        ident,
        1,
        183,
        1,
        0,
        0,
        section_header_offset,
        0,
        64,
        0,
        0,
        64,
        8,
        7,
    )
    path.write_bytes(image)


class DiscoveryContractTests(unittest.TestCase):
    def setUp(self):
        self.trace_document = json.loads(
            (ROOT / "fixtures/platform/async_boundary.causal.json").read_text()
        )
        self.binding = json.loads(
            (ROOT / "fixtures/platform/seeded_boundary.nogate.binding.json").read_text()
        )
        self.policy = json.loads(
            (ROOT / "fixtures/platform/lifetime_discovery.policy.json").read_text()
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.module_path = Path(temporary.name) / "public-structural-fixture.ko"
        build_arm64_relocatable(self.module_path)

    def discover(self):
        return discover_lifetime_candidates(
            self.module_path,
            self.trace_document,
            self.binding,
            self.policy,
        )

    def test_policy_validation_is_deterministic_and_rejects_bad_bounds(self):
        first = validate_discovery_policy(self.policy)
        second = validate_discovery_policy(copy.deepcopy(self.policy))
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "passed")

        policy = copy.deepcopy(self.policy)
        policy["passive_leaf_max_bytes"] = 3
        with self.assertRaisesRegex(ValueError, r"\[4, 256\]"):
            validate_discovery_policy(policy)

    def test_source_free_discovery_emits_points_observations_and_one_edge(self):
        result = self.discover()
        validation = validate_discovery_result(result)
        self.assertEqual(validation["status"], "passed")
        self.assertEqual(validation["point_count"], 2)
        self.assertEqual(validation["edge_count"], 1)
        self.assertEqual(result["boundary"]["selected_dispatcher"], "dispatch")
        self.assertEqual(
            {point["role"] for point in result["discovered_points"]},
            {"post-release-handoff", "pre-acquire-under-lock"},
        )
        self.assertEqual(
            {point["role"] for point in result["observation_points"]},
            {"inside-lock-region", "post-release-object-held", "pre-free"},
        )
        self.assertFalse(result["analysis_contract"]["source_used"])
        self.assertFalse(result["analysis_contract"]["target_function_hints_used"])

    def test_discovery_materializes_a_hash_bound_experiment(self):
        result = self.discover()
        experiment = materialize_discovered_experiment(
            result, self.trace_document, self.binding
        )
        self.assertEqual(
            experiment["schedule"]["schedule_id"],
            experiment["constraints"]["schedule_id"],
        )
        self.assertEqual(
            experiment["binding"]["schedule_sha256"],
            experiment["synthesis"]["schedule_sha256"],
        )
        self.assertEqual(experiment["oracle"]["identity"]["relation"], "equal")
        self.assertEqual(experiment["oracle"]["counters"][0]["minimum"], 2)
        self.assertIn("path_a", experiment["oracle"]["sanitizer"]["required_frames"])
        delayed = [
            action
            for action in experiment["binding"]["actions"]
            if "start_after_signal" in action
        ]
        self.assertEqual(len(delayed), 1)

    def test_researcher_supplied_target_hints_are_rejected(self):
        policy = copy.deepcopy(self.policy)
        policy["candidate_edges"] = ["force-this-edge"]
        with self.assertRaisesRegex(ValueError, "researcher-supplied target hints"):
            discover_lifetime_candidates(
                self.module_path,
                self.trace_document,
                self.binding,
                policy,
            )

    def test_projection_without_a_concurrent_launch_pair_is_rejected(self):
        binding = copy.deepcopy(self.binding)
        binding["actions"][1]["launch_group"] = "separate-group"
        with self.assertRaisesRegex(ValueError, "no qualifying concurrent"):
            discover_lifetime_candidates(
                self.module_path,
                self.trace_document,
                binding,
                self.policy,
            )

    def test_result_integrity_and_materialization_cardinality_fail_closed(self):
        result = self.discover()
        result["boundary"]["selected_dispatcher"] = "tampered"
        with self.assertRaisesRegex(ValueError, "integrity mismatch"):
            validate_discovery_result(result)

        result = self.discover()
        result["candidate_precedence_edges"].append(
            copy.deepcopy(result["candidate_precedence_edges"][0])
        )
        unsigned = copy.deepcopy(result)
        unsigned.pop("integrity")
        result["integrity"] = {"canonical_sha256": discovery_module._digest(unsigned)}
        with self.assertRaisesRegex(ValueError, "requires one edge"):
            materialize_discovered_experiment(
                result, self.trace_document, self.binding
            )

    def test_real_elf_reader_decodes_calls_cfg_and_data_roots(self):
        image = Arm64Relocatable(self.module_path)
        self.assertIn("dispatch", image.functions_by_name)
        self.assertEqual(image.data_function_references(), ["dispatch"])
        calls = image.calls()
        self.assertEqual(len(calls), 17)
        self.assertIn(
            {
                "source": "dispatch",
                "target": "path_a",
                "offset": 0,
                "kind": "call",
                "target_defined": True,
            },
            calls,
        )
        cfg = image.function_cfg(image.functions_by_name["path_a"])
        self.assertEqual(cfg["instruction_count"], 8)
        self.assertGreaterEqual(cfg["basic_block_count"], 1)

    def test_real_elf_reader_rejects_non_elf_and_non_aarch64_inputs(self):
        not_elf = self.module_path.with_name("not-elf.ko")
        not_elf.write_bytes(b"public structural binary-fact fixture")
        with self.assertRaisesRegex(ValueError, "not an ELF"):
            Arm64Relocatable(not_elf)

        data = bytearray(64)
        data[:6] = b"\x7fELF\x02\x01"
        data[16:18] = (1).to_bytes(2, "little")
        data[18:20] = (62).to_bytes(2, "little")
        wrong_arch = self.module_path.with_name("wrong-arch.ko")
        wrong_arch.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "only AArch64"):
            Arm64Relocatable(wrong_arch)


if __name__ == "__main__":
    unittest.main()
