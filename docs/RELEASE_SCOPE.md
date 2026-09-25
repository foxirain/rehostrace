# Public release scope

This repository is built from an allowlist, not by copying a private research tree and deleting selected files.

Included:

- framework source and schemas;
- synthetic protocol and lifetime fixtures;
- intentionally seeded open drivers;
- portable demos, tests, and release tooling.

Excluded:

- proprietary modules, firmware, symbols, manifests, hashes, and captures;
- device identifiers, addresses, credentials, and link keys;
- target-specific offsets, probe layouts, adapters, and schedules;
- build outputs and experiment results;
- unpublished vulnerability reports and exploitability material.

Run `make audit` before packaging and generate `RELEASE_MANIFEST.json` only after the audit succeeds. The manifest intentionally excludes itself, generated outputs, and version-control metadata.
