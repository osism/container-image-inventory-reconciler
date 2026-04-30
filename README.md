# container-image-inventory-reconciler

[![Quay](https://img.shields.io/badge/Quay-osism%2Finventory--reconciler-blue.svg)](https://quay.io/repository/osism/inventory-reconciler)
[![Documentation](https://img.shields.io/static/v1?label=&message=documentation&color=blue)](https://osism.tech/docs/guides/configuration-guide/inventory#reconciler)

## Running unit tests

The Python sources under `files/netbox/` ship with a unit-test suite under
`tests/unit/`. The Zuul `container-image-inventory-reconciler-unit-tests`
job runs the suite in `check`, `gate`, and `periodic-daily`.

To run the tests locally:

```bash
python3 -m venv .venv
.venv/bin/pip install -r files/requirements.txt -r files/test-requirements.txt
.venv/bin/pytest tests/unit
```

Run a single test file:

```bash
.venv/bin/pytest tests/unit/netbox/test_smoke.py
```
