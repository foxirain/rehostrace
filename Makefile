PYTHON ?= python3

.PHONY: test demo bluetooth-demo bluetooth-profiles fuzz-demo bluetooth-parser-fuzz capture-replay analysis-demo target-lowering bluetooth-platform audit manifest verify clean

test:
	$(PYTHON) -m unittest discover -s tests -v

demo:
	$(PYTHON) tools/run_public_platform_demo.py

bluetooth-demo:
	$(PYTHON) tools/run_bluetooth_subsystem_demo.py

bluetooth-profiles:
	$(PYTHON) tools/run_bluetooth_profile_demo.py

fuzz-demo:
	$(PYTHON) tools/run_public_fuzz_demo.py

bluetooth-parser-fuzz:
	$(PYTHON) tools/run_bluetooth_parser_fuzz_demo.py

capture-replay:
	$(PYTHON) tools/run_capture_replay_demo.py

analysis-demo:
	$(PYTHON) tools/run_analysis_pipeline_demo.py

target-lowering:
	$(PYTHON) tools/run_target_lowering_demo.py

bluetooth-platform:
	$(PYTHON) tools/run_full_bluetooth_platform_demo.py

audit:
	$(PYTHON) tools/audit_framework_release.py .

manifest:
	$(PYTHON) tools/generate_release_manifest.py . RELEASE_MANIFEST.json

verify: test demo bluetooth-demo bluetooth-platform target-lowering audit manifest

clean:
	$(PYTHON) -c 'import shutil; shutil.rmtree("out", ignore_errors=True)'
