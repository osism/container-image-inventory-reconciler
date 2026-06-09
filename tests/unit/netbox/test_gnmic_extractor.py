# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/extractors/gnmic_extractor.py.

The extractor builds a gnmic target config for switches tagged
``managed-by-metalbox``. It reads interfaces / IP addresses through a pynetbox
session, faked here by ``make_fake_api`` (plain lists) or, where call arguments
matter, by ``MagicMock`` filters. The module-level ``loguru`` logger is patched
with a ``MagicMock`` via ``monkeypatch`` (restored after each test) only where a
log assertion documents the branch taken.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from extractors.gnmic_extractor import GnmicExtractor

from .conftest import make_device, make_fake_api, make_interface, make_ip


@pytest.fixture
def mock_logger(monkeypatch):
    """Replace the module-level loguru logger with a MagicMock."""
    logger = MagicMock()
    monkeypatch.setattr("extractors.gnmic_extractor.logger", logger)
    return logger


def _oob_interface(id=10):
    """A managed OOB interface: mgmt_only with the managed-by-osism tag."""
    return make_interface(id=id, mgmt_only=True, tags=("managed-by-osism",))


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestInit:
    def test_defaults(self):
        extractor = GnmicExtractor()
        assert extractor.api is None
        assert extractor.netbox_client is None

    def test_custom_values_are_stored(self):
        api = object()
        client = object()
        extractor = GnmicExtractor(api=api, netbox_client=client)
        assert extractor.api is api
        assert extractor.netbox_client is client


# ---------------------------------------------------------------------------
# _has_metalbox_tag
# ---------------------------------------------------------------------------


class TestHasMetalboxTag:
    def test_no_tags_attribute_returns_false(self):
        device = SimpleNamespace(name="d1")  # no .tags attribute at all
        assert GnmicExtractor()._has_metalbox_tag(device) is False

    def test_empty_tags_returns_false(self):
        device = make_device(1, "d1", tags=())
        assert GnmicExtractor()._has_metalbox_tag(device) is False

    def test_tags_without_metalbox_returns_false(self):
        device = make_device(1, "d1", tags=("managed-by-osism", "production"))
        assert GnmicExtractor()._has_metalbox_tag(device) is False

    def test_tags_with_metalbox_returns_true(self):
        device = make_device(1, "d1", tags=("production", "managed-by-metalbox"))
        assert GnmicExtractor()._has_metalbox_tag(device) is True


# ---------------------------------------------------------------------------
# _get_hostname
#
# This helper inlines the inventory_hostname logic and deliberately diverges
# from utils.get_inventory_hostname: it is hasattr-guarded (tolerates devices
# without a custom_fields attribute, see
# test_no_custom_fields_attribute_falls_back_to_name) and returns the raw
# value without str coercion. Do not consolidate the two.
# ---------------------------------------------------------------------------


class TestGetHostname:
    def test_inventory_hostname_custom_field_used(self):
        device = make_device(
            1, "raw-name", custom_fields={"inventory_hostname": "pretty"}
        )
        assert GnmicExtractor()._get_hostname(device) == "pretty"

    def test_empty_inventory_hostname_falls_back_to_name(self):
        device = make_device(1, "raw-name", custom_fields={"inventory_hostname": ""})
        assert GnmicExtractor()._get_hostname(device) == "raw-name"

    def test_absent_inventory_hostname_falls_back_to_name(self):
        device = make_device(1, "raw-name", custom_fields={"other": "x"})
        assert GnmicExtractor()._get_hostname(device) == "raw-name"

    def test_none_custom_fields_falls_back_to_name(self):
        device = make_device(1, "raw-name", custom_fields=None)
        assert GnmicExtractor()._get_hostname(device) == "raw-name"

    def test_no_custom_fields_attribute_falls_back_to_name(self):
        device = SimpleNamespace(name="raw-name")  # no .custom_fields attribute
        assert GnmicExtractor()._get_hostname(device) == "raw-name"


# ---------------------------------------------------------------------------
# _is_managed_oob_interface
# ---------------------------------------------------------------------------


class TestIsManagedOobInterface:
    def test_no_tags_returns_false(self):
        iface = make_interface(id=1, mgmt_only=True, tags=())
        assert GnmicExtractor()._is_managed_oob_interface(iface) is False

    def test_not_mgmt_only_returns_false(self):
        iface = make_interface(id=1, mgmt_only=False, tags=("managed-by-osism",))
        assert GnmicExtractor()._is_managed_oob_interface(iface) is False

    def test_mgmt_only_without_osism_tag_returns_false(self):
        iface = make_interface(id=1, mgmt_only=True, tags=("managed-by-metalbox",))
        assert GnmicExtractor()._is_managed_oob_interface(iface) is False

    def test_mgmt_only_with_osism_tag_returns_true(self):
        iface = make_interface(id=1, mgmt_only=True, tags=("managed-by-osism", "x"))
        assert GnmicExtractor()._is_managed_oob_interface(iface) is True


# ---------------------------------------------------------------------------
# _get_oob_ip
# ---------------------------------------------------------------------------


class TestGetOobIp:
    def test_no_api_returns_none_and_warns(self, mock_logger):
        device = make_device(1, "d1")
        assert GnmicExtractor(api=None)._get_oob_ip(device) is None
        assert mock_logger.warning.called

    def test_managed_oob_interface_ip_returned(self):
        iface = _oob_interface(id=10)
        api = make_fake_api(
            interfaces=[iface],
            ips_by_interface={10: [make_ip("192.0.2.10/24")]},
        )
        assert GnmicExtractor(api=api)._get_oob_ip(make_device(1, "d1")) == "192.0.2.10"

    def test_non_managed_interface_skipped(self):
        iface = make_interface(id=10, mgmt_only=False, tags=("managed-by-osism",))
        api = make_fake_api(
            interfaces=[iface],
            ips_by_interface={10: [make_ip("192.0.2.10/24")]},
        )
        assert GnmicExtractor(api=api)._get_oob_ip(make_device(1, "d1")) is None

    def test_managed_interface_without_ips_returns_none(self):
        iface = _oob_interface(id=10)
        api = make_fake_api(interfaces=[iface], ips_by_interface={10: []})
        assert GnmicExtractor(api=api)._get_oob_ip(make_device(1, "d1")) is None

    def test_ip_without_address_skipped_later_valid_returned(self):
        iface = _oob_interface(id=10)
        ips = [SimpleNamespace(), make_ip(""), make_ip("192.0.2.20/24")]
        api = make_fake_api(interfaces=[iface], ips_by_interface={10: ips})
        assert GnmicExtractor(api=api)._get_oob_ip(make_device(1, "d1")) == "192.0.2.20"

    def test_interface_filter_exception_returns_none_and_warns(self, mock_logger):
        api = SimpleNamespace(
            dcim=SimpleNamespace(
                interfaces=SimpleNamespace(
                    filter=MagicMock(side_effect=RuntimeError("boom")),
                ),
            ),
        )
        assert GnmicExtractor(api=api)._get_oob_ip(make_device(1, "d1")) is None
        assert mock_logger.warning.called

    def test_filter_called_with_expected_ids(self):
        iface = _oob_interface(id=10)
        iface_filter = MagicMock(return_value=[iface])
        ip_filter = MagicMock(return_value=[make_ip("192.0.2.10/24")])
        api = SimpleNamespace(
            dcim=SimpleNamespace(interfaces=SimpleNamespace(filter=iface_filter)),
            ipam=SimpleNamespace(ip_addresses=SimpleNamespace(filter=ip_filter)),
        )
        result = GnmicExtractor(api=api)._get_oob_ip(make_device(7, "d1"))
        assert result == "192.0.2.10"
        iface_filter.assert_called_once_with(device_id=7)
        ip_filter.assert_called_once_with(interface_id=10)


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------


class TestExtract:
    def test_no_metalbox_tag_returns_none_without_api_calls(self, mock_logger):
        iface_filter = MagicMock()
        api = SimpleNamespace(
            dcim=SimpleNamespace(interfaces=SimpleNamespace(filter=iface_filter)),
        )
        device = make_device(1, "d1", tags=("managed-by-osism",))
        assert GnmicExtractor(api=api).extract(device) is None
        iface_filter.assert_not_called()  # _get_oob_ip never reached
        assert mock_logger.debug.called

    def test_tag_but_no_oob_ip_returns_none_and_warns(self, mock_logger):
        api = make_fake_api(interfaces=[], ips_by_interface={})
        device = make_device(1, "d1", tags=("managed-by-metalbox",))
        assert GnmicExtractor(api=api).extract(device) is None
        assert mock_logger.warning.called

    def test_full_gnmic_config_shape(self):
        iface = _oob_interface(id=10)
        api = make_fake_api(
            interfaces=[iface],
            ips_by_interface={10: [make_ip("192.0.2.10/24")]},
        )
        device = make_device(1, "switch-1", tags=("managed-by-metalbox",))
        result = GnmicExtractor(api=api).extract(device)
        assert result == {
            "gnmic_targets__switch-1": {
                "192.0.2.10:8080": {
                    "username": "admin",
                    "password": "YourPaSsWoRd",
                    "encoding": "json",
                    "subscriptions": ["all-interfaces"],
                }
            }
        }

    def test_hostname_honors_inventory_hostname_custom_field(self):
        iface = _oob_interface(id=10)
        api = make_fake_api(
            interfaces=[iface],
            ips_by_interface={10: [make_ip("192.0.2.10/24")]},
        )
        device = make_device(
            1,
            "raw-name",
            tags=("managed-by-metalbox",),
            custom_fields={"inventory_hostname": "pretty"},
        )
        result = GnmicExtractor(api=api).extract(device)
        assert "gnmic_targets__pretty" in result

    def test_extra_kwargs_are_ignored(self):
        iface = _oob_interface(id=10)
        api = make_fake_api(
            interfaces=[iface],
            ips_by_interface={10: [make_ip("192.0.2.10/24")]},
        )
        device = make_device(1, "switch-1", tags=("managed-by-metalbox",))
        result = GnmicExtractor(api=api).extract(device, unused="x")
        assert "gnmic_targets__switch-1" in result


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
