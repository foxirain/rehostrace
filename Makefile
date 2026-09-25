PYTHON ?= python3

.PHONY: test demo bluetooth-demo bluetooth-profiles audit manifest verify clean

test:
	$(PYTHON) -m unittest discover -s tests -v

demo:
	$(PYTHON) tools/run_public_platform_demo.py

bluetooth-demo:
	$(PYTHON) tools/run_bluetooth_subsystem_demo.py

bluetooth-profiles:
	$(PYTHON) tools/run_bluetooth_profile_demo.py

audit:
	$(PYTHON) tools/audit_framework_release.py .

manifest:
	$(PYTHON) tools/generate_release_manifest.py . RELEASE_MANIFEST.json

verify: test demo bluetooth-demo bluetooth-profiles audit manifest

clean:
	$(PYTHON) -c 'import shutil; shutil.rmtree("out", ignore_errors=True)'
