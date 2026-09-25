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
from .capture import CaptureSession
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
    "AvdtpProtocolPack",
    "BluetoothCoreAdapter",
    "BluetoothStateError",
    "CaptureSession",
    "CausalTrace",
    "GattProtocolPack",
    "HciProtocolPack",
    "L2capProtocolPack",
    "RecordingAdapter",
    "ReplayEngine",
    "ReplayError",
    "SdpProtocolPack",
    "build_receipt",
    "canonical_sha256",
    "compile_ablation",
    "compile_binding",
    "compile_evidence_transfer_bridge",
    "compile_observer_calibration",
    "compile_schedule",
    "compose_bluetooth_traces",
    "default_bluetooth_registrations",
    "discover_lifetime_candidates",
    "evaluate_oracle",
    "gate_key",
    "generate_bluetooth_linearizations",
    "linearization_pair_coverage",
    "materialize_discovered_experiment",
    "plan_exhaustive_search",
    "render_ablation_header",
    "render_binding_header",
    "render_c_header",
    "summarize_search",
    "synthesize_schedule",
    "validate_binding",
    "validate_bluetooth_composition",
    "validate_constraints",
    "validate_discovery_policy",
    "validate_discovery_result",
    "validate_evidence_transfer_bridge",
    "validate_evidence_transfer_policy",
    "validate_observer_calibration",
    "validate_observer_calibration_policy",
    "validate_oracle",
    "validate_profile_catalog",
    "validate_protocol_pack",
    "validate_receipt",
    "validate_schedule",
    "validate_search_manifest",
    "validate_trace",
    "verify_receipt_artifacts",
]
