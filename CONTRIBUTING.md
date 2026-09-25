# Contributing

Contributions should preserve the distinction between a mechanism demonstration and a target claim.

For a new adapter or fixture:

1. document actors, resources, clock domains, and causal edges;
2. provide a public synthetic or openly licensed fixture;
3. add positive and fail-closed negative tests;
4. define the observation oracle and object-identity rules;
5. emit an evidence receipt with explicit allowed, forbidden, and asserted claims;
6. state missing fidelity dimensions and observer effects; and
7. run `make verify` before submitting a change.

Do not commit generated kernel modules, object files, build trees, firmware, packet captures, credentials, link keys, private traces, unpublished exploit schedules, or absolute workstation paths. `tools/audit_framework_release.py` enforces the release subset but does not replace human review.

Protocol packs and schemas must remain data-only and deterministic. Changes that alter canonical hashing or event-order semantics need migration notes and compatibility tests.
