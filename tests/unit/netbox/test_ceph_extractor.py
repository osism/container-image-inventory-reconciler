# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/extractors/ceph_extractor.py.

The extractor never generates data and never writes back to NetBox. It only
resolves a value: the ``ceph_parameters`` custom field, if set to a non-empty
dict, takes priority and is returned as-is (not merged); otherwise it falls
back to the ``ceph_parameters`` key in ``device.config_context``.
"""

import pytest

from extractors.ceph_extractor import CephExtractor

from .conftest import make_device


def _device(*, custom_fields=None, config_context=None):
    """Build a device stub exposing both custom_fields and config_context."""
    device = make_device(1, "node1", custom_fields=custom_fields)
    device.config_context = config_context
    return device


class TestExtract:
    def test_custom_field_used_when_set(self):
        cf_value = {"ceph_osd_devices": ["/dev/sdb"]}
        device = _device(custom_fields={"ceph_parameters": cf_value})
        assert CephExtractor().extract(device) == cf_value

    def test_custom_field_takes_priority_over_config_context(self):
        cf_value = {"ceph_osd_devices": ["/dev/sdb"]}
        cc_value = {"ceph_osd_devices": ["/dev/sdc"]}
        device = _device(
            custom_fields={"ceph_parameters": cf_value},
            config_context={"ceph_parameters": cc_value},
        )
        # Custom field replaces config_context entirely - not merged.
        assert CephExtractor().extract(device) == cf_value

    def test_falls_back_to_config_context_when_custom_field_unset(self):
        cc_value = {"ceph_osd_devices": ["/dev/sdc"]}
        device = _device(config_context={"ceph_parameters": cc_value})
        assert CephExtractor().extract(device) == cc_value

    @pytest.mark.parametrize("cf_value", [None, "", 0, "a string", ["a", "b"]])
    def test_non_dict_custom_field_falls_back_to_config_context(self, cf_value):
        cc_value = {"ceph_osd_devices": ["/dev/sdc"]}
        device = _device(
            custom_fields={"ceph_parameters": cf_value},
            config_context={"ceph_parameters": cc_value},
        )
        assert CephExtractor().extract(device) == cc_value

    def test_empty_dict_custom_field_falls_back_to_config_context(self):
        # An explicitly empty custom field ({}) is treated as unset.
        cc_value = {"ceph_osd_devices": ["/dev/sdc"]}
        device = _device(
            custom_fields={"ceph_parameters": {}},
            config_context={"ceph_parameters": cc_value},
        )
        assert CephExtractor().extract(device) == cc_value

    def test_none_custom_fields_falls_back_to_config_context(self):
        cc_value = {"ceph_osd_devices": ["/dev/sdc"]}
        device = _device(custom_fields=None, config_context={"ceph_parameters": cc_value})
        assert CephExtractor().extract(device) == cc_value

    @pytest.mark.parametrize("cc_value", [None, "", 0, "a string", ["a", "b"]])
    def test_non_dict_config_context_value_returns_none(self, cc_value):
        device = _device(config_context={"ceph_parameters": cc_value})
        assert CephExtractor().extract(device) is None

    @pytest.mark.parametrize("config_context", [None, "a string", ["a", "b"]])
    def test_non_dict_config_context_returns_none(self, config_context):
        device = _device(config_context=config_context)
        assert CephExtractor().extract(device) is None

    def test_missing_ceph_parameters_key_returns_none(self):
        device = _device(
            custom_fields={"other": 1}, config_context={"other": 1}
        )
        assert CephExtractor().extract(device) is None

    def test_extra_kwargs_are_ignored(self):
        cc_value = {"ceph_osd_devices": ["/dev/sdc"]}
        device = _device(config_context={"ceph_parameters": cc_value})
        assert CephExtractor().extract(device, unused="x") == cc_value


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
