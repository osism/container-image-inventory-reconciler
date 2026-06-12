# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/extractors/frr_extractor.py.

The extractor turns a device's NetBox interfaces (loopback0, VRF dummies and
uplinks) into the auto-generated ``frr_parameters``. It reads interfaces and IP
addresses through a pre-seeded real ``BulkDataLoader`` (its ``device_interfaces``
/ ``interface_ips`` caches are plain dicts, so the genuine cache round-trip is
exercised), resolves a remote device's custom fields through ``dcim.devices.get``
on the faked API, and uses the real ``CustomFieldExtractor`` / ``utils.deep_merge``
- the very logic these tests verify. The module-level ``loguru`` logger is patched
with a ``MagicMock`` via ``monkeypatch`` (restored after each test) only where a
log assertion documents the branch taken.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from bulk_loader import BulkDataLoader
from extractors.frr_extractor import ASNumberCalculator, FRRExtractor, InterfaceFilter

from .conftest import make_device, make_fake_api, make_interface, make_tag


@pytest.fixture
def mock_logger(monkeypatch):
    """Replace the module-level loguru logger with a MagicMock."""
    logger = MagicMock()
    monkeypatch.setattr("extractors.frr_extractor.logger", logger)
    return logger


def _extractor(*, api=None, netbox_client=None, loader=None):
    """Build an FRRExtractor with a fresh, empty BulkDataLoader by default."""
    if loader is None:
        loader = BulkDataLoader(make_fake_api())
    return FRRExtractor(api=api, netbox_client=netbox_client, bulk_loader=loader)


# ---------------------------------------------------------------------------
# ASNumberCalculator.from_ipv4
# ---------------------------------------------------------------------------


class TestASNumberCalculatorFromIpv4:
    def test_address_with_cidr_default_prefix(self):
        assert ASNumberCalculator.from_ipv4("192.168.45.123/32") == 4200045123

    def test_address_without_cidr(self):
        assert ASNumberCalculator.from_ipv4("192.168.45.123") == 4200045123

    def test_low_octets_are_zero_padded(self):
        assert ASNumberCalculator.from_ipv4("10.0.5.9") == 4200005009

    def test_custom_prefix(self):
        assert ASNumberCalculator.from_ipv4("192.168.45.123", prefix=4201) == 4201045123

    def test_too_few_octets_raises(self):
        with pytest.raises(ValueError) as exc_info:
            ASNumberCalculator.from_ipv4("192.168.45")
        assert "192.168.45" in str(exc_info.value)

    def test_too_many_octets_raises(self):
        with pytest.raises(ValueError) as exc_info:
            ASNumberCalculator.from_ipv4("1.2.3.4.5")
        assert "1.2.3.4.5" in str(exc_info.value)

    def test_non_numeric_octet_raises(self):
        with pytest.raises(ValueError) as exc_info:
            ASNumberCalculator.from_ipv4("192.168.x.1")
        assert "192.168.x.1" in str(exc_info.value)

    def test_octet_out_of_range_raises(self):
        with pytest.raises(ValueError) as exc_info:
            ASNumberCalculator.from_ipv4("192.168.300.1")
        assert "192.168.300.1" in str(exc_info.value)


# ---------------------------------------------------------------------------
# InterfaceFilter.has_managed_tag
# ---------------------------------------------------------------------------


class TestHasManagedTag:
    def test_no_tags_attribute_returns_false(self):
        iface = SimpleNamespace()  # no .tags attribute at all
        assert InterfaceFilter.has_managed_tag(iface) is False

    def test_empty_tags_returns_false(self):
        iface = make_interface(id=1, tags=())
        assert InterfaceFilter.has_managed_tag(iface) is False

    def test_tags_without_managed_returns_false(self):
        iface = make_interface(id=1, tags=("production", "other"))
        assert InterfaceFilter.has_managed_tag(iface) is False

    def test_tags_with_managed_returns_true(self):
        iface = make_interface(id=1, tags=("production", "managed-by-osism"))
        assert InterfaceFilter.has_managed_tag(iface) is True


# ---------------------------------------------------------------------------
# InterfaceFilter.is_valid_uplink
# ---------------------------------------------------------------------------


def _valid_uplink_interface(**overrides):
    """A fully valid uplink: managed tag, label, endpoints, enabled, not mgmt."""
    kwargs = dict(
        id=1,
        tags=("managed-by-osism",),
        label="data1",
        connected_endpoints=[SimpleNamespace(device=make_device(2, "remote"))],
        enabled=True,
        mgmt_only=False,
    )
    kwargs.update(overrides)
    return make_interface(**kwargs)


class TestIsValidUplink:
    def test_fully_valid_uplink_returns_true(self):
        assert InterfaceFilter.is_valid_uplink(_valid_uplink_interface()) is True

    def test_missing_managed_tag_returns_false(self):
        assert (
            InterfaceFilter.is_valid_uplink(_valid_uplink_interface(tags=())) is False
        )

    def test_missing_label_returns_false(self):
        assert (
            InterfaceFilter.is_valid_uplink(_valid_uplink_interface(label=None))
            is False
        )

    def test_empty_label_returns_false(self):
        assert (
            InterfaceFilter.is_valid_uplink(_valid_uplink_interface(label="")) is False
        )

    def test_connected_endpoints_attr_absent_returns_false(self):
        # Hand-built stub without a connected_endpoints attribute.
        iface = SimpleNamespace(tags=[make_tag("managed-by-osism")], label="data1")
        assert InterfaceFilter.is_valid_uplink(iface) is False

    def test_empty_connected_endpoints_returns_false(self):
        assert (
            InterfaceFilter.is_valid_uplink(
                _valid_uplink_interface(connected_endpoints=[])
            )
            is False
        )

    def test_disabled_returns_false(self):
        assert (
            InterfaceFilter.is_valid_uplink(_valid_uplink_interface(enabled=False))
            is False
        )

    def test_enabled_attr_absent_treated_as_true(self):
        # Hand-built stub without enabled / mgmt_only attributes -> defaults apply.
        iface = SimpleNamespace(
            tags=[make_tag("managed-by-osism")],
            label="data1",
            connected_endpoints=[object()],
        )
        assert InterfaceFilter.is_valid_uplink(iface) is True

    def test_mgmt_only_true_returns_false(self):
        assert (
            InterfaceFilter.is_valid_uplink(_valid_uplink_interface(mgmt_only=True))
            is False
        )


# ---------------------------------------------------------------------------
# FRRExtractor.__init__
# ---------------------------------------------------------------------------


class TestFrrInit:
    def test_stores_collaborators_and_builds_helpers(self):
        api = object()
        client = object()
        loader = BulkDataLoader(make_fake_api())
        extractor = FRRExtractor(api=api, netbox_client=client, bulk_loader=loader)
        assert extractor.api is api
        assert extractor.netbox_client is client
        assert extractor.bulk_loader is loader
        assert isinstance(extractor.as_calculator, ASNumberCalculator)
        assert isinstance(extractor.interface_filter, InterfaceFilter)


# ---------------------------------------------------------------------------
# FRRExtractor._calculate_as_number
# ---------------------------------------------------------------------------


class TestCalculateAsNumber:
    def test_priority1_frr_local_as_wins_over_calculation(self):
        # frr_local_as custom field is returned directly, even with an ipv4.
        device = make_device(1, "d1", custom_fields={"frr_local_as": 65001})
        result = _extractor()._calculate_as_number(device, "192.168.45.123/32", 4200)
        assert result == 65001

    def test_priority2_cached_frr_parameters_returned_and_debug_logged(
        self, mock_logger
    ):
        device = make_device(
            1, "d1", custom_fields={"frr_parameters": {"frr_local_as": 64500}}
        )
        result = _extractor()._calculate_as_number(device, "192.168.45.123/32", 4200)
        assert result == 64500
        assert mock_logger.debug.called

    def test_priority2_guard_non_dict_falls_through_to_calculation(self):
        device = make_device(1, "d1", custom_fields={"frr_parameters": "not-a-dict"})
        result = _extractor()._calculate_as_number(device, "192.168.45.123/32", 4200)
        assert result == 4200045123

    def test_priority2_guard_dict_without_key_falls_through(self):
        device = make_device(1, "d1", custom_fields={"frr_parameters": {"other": 1}})
        result = _extractor()._calculate_as_number(device, "192.168.45.123/32", 4200)
        assert result == 4200045123

    def test_priority3_calculates_from_ipv4(self):
        device = make_device(1, "d1", custom_fields={})
        result = _extractor()._calculate_as_number(device, "192.168.45.123/32", 4200)
        assert result == 4200045123

    def test_priority3_invalid_ipv4_returns_none_and_warns(self, mock_logger):
        device = make_device(1, "d1", custom_fields={})
        result = _extractor()._calculate_as_number(device, "192.168.45", 4200)
        assert result is None
        assert mock_logger.warning.called

    def test_no_custom_fields_and_no_ipv4_returns_none(self):
        device = make_device(1, "d1", custom_fields={})
        assert _extractor()._calculate_as_number(device, None, 4200) is None


# ---------------------------------------------------------------------------
# FRRExtractor._get_frr_type
# ---------------------------------------------------------------------------


class TestGetFrrType:
    def test_frr_type_from_config_context(self):
        device = make_device(
            1, "d1", config_context={"frr_parameters": {"frr_type": "yrzn-spine"}}
        )
        assert _extractor()._get_frr_type(device) == "yrzn-spine"

    def test_no_config_context_returns_none(self):
        device = make_device(1, "d1", config_context=None)
        assert _extractor()._get_frr_type(device) is None

    def test_frr_parameters_not_a_dict_returns_none(self):
        device = make_device(1, "d1", config_context={"frr_parameters": "nope"})
        assert _extractor()._get_frr_type(device) is None

    def test_no_frr_parameters_returns_none(self):
        device = make_device(1, "d1", config_context={"other": {}})
        assert _extractor()._get_frr_type(device) is None

    def test_frr_parameters_without_frr_type_returns_none(self):
        device = make_device(1, "d1", config_context={"frr_parameters": {"x": 1}})
        assert _extractor()._get_frr_type(device) is None


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
