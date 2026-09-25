"""Public SDK for causality-preserving replay and evidence receipts."""

from .ablation import compile_ablation, render_ablation_header
from .binding import compile_binding, render_binding_header, validate_binding
from .bluetooth import (
    AttProtocolPack,
    AvdtpProtocolPack,
    BluetoothCoreAdapter,
    BluetoothStateError,
    GattProtocolPack,
    HciProtocolPack,
    L2capProtocolPack,
    SdpProtocolPack,
    default_bluetooth_registrations,
    validate_profile_catalog,
    validate_protocol_pack,
)
from .bluetooth_composition import (
    compose_bluetooth_traces,
    generate_bluetooth_linearizations,
    linearization_pair_coverage,
    validate_bluetooth_composition,
)
from .bluetooth_parsers import (
    BluetoothPacketParserRegistry,
    PacketParseError,
    ParsedPacket,
    built_in_packet_parser_registry,
    parse_a2dp_rtp,
    parse_avrcp,
    parse_hfp_at,
    parse_le_iso,
    parse_rfcomm,
    parse_smp,
)
from .bluetooth_profiles import (
    A2dpProtocolPack,
    AvrcpProtocolPack,
    HfpProtocolPack,
    LeAudioProtocolPack,
    RfcommProtocolPack,
    SmpProtocolPack,
)
from .bluetooth_registry import BluetoothPackRegistry, built_in_bluetooth_registry
from .capture import CaptureSession
from .capture_bundle import compile_capture_bundle, validate_capture_bundle
from .cfg import analyze_lifetime_cfg, synthesize_lifetime_schedules, validate_binary_cfg
from .differential import compare_target_manifests, validate_target_manifest
from .discovery import (
    Arm64Relocatable,
    discover_lifetime_candidates,
    materialize_discovered_experiment,
    validate_discovery_policy,
    validate_discovery_result,
)
from .evidence_bridge import (
    compile_evidence_transfer_bridge,
    validate_evidence_transfer_bridge,
    validate_evidence_transfer_policy,
)
from .fuzz import CoverageGuidedFuzzer, FuzzOutcome, validate_fuzz_policy
from .harness import compile_harness_plan, validate_harness_plan
from .lowering import (
    compile_target_controller,
    render_target_controller_header,
    validate_target_lowering,
)
from .model import CausalTrace, canonical_sha256, validate_trace
from .observer import (
    compile_observer_calibration,
    validate_observer_calibration,
    validate_observer_calibration_policy,
)
from .oracle import evaluate_oracle, validate_oracle
from .receipt import build_receipt, validate_receipt, verify_receipt_artifacts
from .replay import RecordingAdapter, ReplayEngine, ReplayError
from .schedule import compile_schedule, render_c_header, validate_schedule
from .search import (
    gate_key,
    plan_exhaustive_search,
    summarize_search,
    validate_search_manifest,
)
from .synthesis import synthesize_schedule, validate_constraints

__all__ = [
    "Arm64Relocatable",
    "AttProtocolPack",
    "A2dpProtocolPack",
    "AvdtpProtocolPack",
    "AvrcpProtocolPack",
    "BluetoothPackRegistry",
    "BluetoothPacketParserRegistry",
    "BluetoothCoreAdapter",
    "BluetoothStateError",
    "CaptureSession",
    "CausalTrace",
    "CoverageGuidedFuzzer",
    "FuzzOutcome",
    "GattProtocolPack",
    "HciProtocolPack",
    "HfpProtocolPack",
    "LeAudioProtocolPack",
    "L2capProtocolPack",
    "PacketParseError",
    "ParsedPacket",
    "RecordingAdapter",
    "ReplayEngine",
    "ReplayError",
    "RfcommProtocolPack",
    "SdpProtocolPack",
    "SmpProtocolPack",
    "build_receipt",
    "analyze_lifetime_cfg",
    "built_in_bluetooth_registry",
    "built_in_packet_parser_registry",
    "canonical_sha256",
    "compile_ablation",
    "compile_binding",
    "compile_capture_bundle",
    "compile_harness_plan",
    "compile_target_controller",
    "compile_evidence_transfer_bridge",
    "compile_observer_calibration",
    "compile_schedule",
    "compose_bluetooth_traces",
    "compare_target_manifests",
    "default_bluetooth_registrations",
    "discover_lifetime_candidates",
    "evaluate_oracle",
    "gate_key",
    "generate_bluetooth_linearizations",
    "linearization_pair_coverage",
    "materialize_discovered_experiment",
    "plan_exhaustive_search",
    "parse_a2dp_rtp",
    "parse_avrcp",
    "parse_hfp_at",
    "parse_le_iso",
    "parse_rfcomm",
    "parse_smp",
    "render_ablation_header",
    "render_binding_header",
    "render_c_header",
    "render_target_controller_header",
    "summarize_search",
    "synthesize_schedule",
    "synthesize_lifetime_schedules",
    "validate_binding",
    "validate_binary_cfg",
    "validate_capture_bundle",
    "validate_bluetooth_composition",
    "validate_constraints",
    "validate_discovery_policy",
    "validate_discovery_result",
    "validate_evidence_transfer_bridge",
    "validate_evidence_transfer_policy",
    "validate_fuzz_policy",
    "validate_harness_plan",
    "validate_observer_calibration",
    "validate_observer_calibration_policy",
    "validate_oracle",
    "validate_profile_catalog",
    "validate_protocol_pack",
    "validate_receipt",
    "validate_schedule",
    "validate_search_manifest",
    "validate_trace",
    "validate_target_manifest",
    "validate_target_lowering",
    "verify_receipt_artifacts",
]
