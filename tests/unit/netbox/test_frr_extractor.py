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

from .conftest import (
    make_device,
    make_fake_api,
    make_iface_type,
    make_interface,
    make_ip,
    make_tag,
    make_vrf,
)


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


# ---------------------------------------------------------------------------
# FRRExtractor._get_loopback0_addresses
# ---------------------------------------------------------------------------


def _loader_with(device, interfaces, ips_by_id=None):
    """Build a real BulkDataLoader pre-seeded for a single device."""
    loader = BulkDataLoader(make_fake_api())
    loader.device_interfaces[device.id] = list(interfaces)
    for iface_id, ips in (ips_by_id or {}).items():
        loader.interface_ips[iface_id] = list(ips)
    return loader


class TestGetLoopback0Addresses:
    def test_no_api_returns_none_pair_and_warns(self, mock_logger):
        device = make_device(1, "d1")
        result = _extractor(api=None)._get_loopback0_addresses(device)
        assert result == {"ipv4": None, "ipv6": None}
        assert mock_logger.warning.called

    def test_ipv4_kept_with_prefix_ipv6_mask_stripped(self):
        # The asymmetry is deliberate: IPv4 is stored verbatim (line 228),
        # IPv6 has its mask stripped (line 225).
        device = make_device(1, "d1")
        lo = make_interface(id=10, name="loopback0")
        loader = _loader_with(
            device,
            [lo],
            {10: [make_ip("192.168.45.123/32"), make_ip("2001:db8::1/128")]},
        )
        result = _extractor(api=object(), loader=loader)._get_loopback0_addresses(
            device
        )
        assert result["ipv4"] == "192.168.45.123/32"
        assert result["ipv6"] == "2001:db8::1"

    def test_api_fallback_when_cache_empty(self):
        # Empty loader -> both the interface and IP lookups fall back to the API.
        device = make_device(1, "d1")
        lo = make_interface(id=10, name="loopback0")
        api = make_fake_api(
            interfaces=[lo], ips_by_interface={10: [make_ip("192.168.45.123/32")]}
        )
        loader = BulkDataLoader(make_fake_api())
        result = _extractor(api=api, loader=loader)._get_loopback0_addresses(device)
        assert result["ipv4"] == "192.168.45.123/32"

    def test_no_loopback0_returns_none_pair_and_debug_logs(self, mock_logger):
        device = make_device(1, "d1")
        eth = make_interface(id=11, name="eth11")
        loader = _loader_with(device, [eth])
        result = _extractor(api=object(), loader=loader)._get_loopback0_addresses(
            device
        )
        assert result == {"ipv4": None, "ipv6": None}
        assert mock_logger.debug.called

    def test_name_match_is_case_insensitive(self):
        device = make_device(1, "d1")
        lo = make_interface(id=10, name="Loopback0")
        loader = _loader_with(device, [lo], {10: [make_ip("192.168.45.123/32")]})
        result = _extractor(api=object(), loader=loader)._get_loopback0_addresses(
            device
        )
        assert result["ipv4"] == "192.168.45.123/32"

    def test_multiple_ipv4_keeps_first(self):
        device = make_device(1, "d1")
        lo = make_interface(id=10, name="loopback0")
        loader = _loader_with(
            device,
            [lo],
            {10: [make_ip("192.168.45.1/32"), make_ip("192.168.45.2/32")]},
        )
        result = _extractor(api=object(), loader=loader)._get_loopback0_addresses(
            device
        )
        assert result["ipv4"] == "192.168.45.1/32"

    def test_ip_with_falsy_address_is_skipped(self):
        device = make_device(1, "d1")
        lo = make_interface(id=10, name="loopback0")
        loader = _loader_with(
            device, [lo], {10: [make_ip(""), make_ip("192.168.45.123/32")]}
        )
        result = _extractor(api=object(), loader=loader)._get_loopback0_addresses(
            device
        )
        assert result["ipv4"] == "192.168.45.123/32"

    def test_lookup_exception_returns_none_pair_and_errors(self, mock_logger):
        device = make_device(1, "d1")
        api = MagicMock()
        api.dcim.interfaces.filter.side_effect = RuntimeError("boom")
        loader = BulkDataLoader(make_fake_api())  # empty -> API fallback raises
        result = _extractor(api=api, loader=loader)._get_loopback0_addresses(device)
        assert result == {"ipv4": None, "ipv6": None}
        assert mock_logger.error.called


# ---------------------------------------------------------------------------
# FRRExtractor._get_vrf_loopback_addresses
# ---------------------------------------------------------------------------


def _vrf_dummy(**overrides):
    """A qualifying VRF dummy: managed, virtual, vrf42, no MAC / VLAN."""
    kwargs = dict(
        id=20,
        name="lo-vrf-a",
        tags=("managed-by-osism",),
        type=make_iface_type("virtual"),
        vrf=make_vrf("vrf42"),
    )
    kwargs.update(overrides)
    return make_interface(**kwargs)


class TestGetVrfLoopbackAddresses:
    def test_no_api_returns_empty(self):
        assert (
            _extractor(api=None)._get_vrf_loopback_addresses(make_device(1, "d")) == []
        )

    def test_no_interfaces_returns_empty(self):
        device = make_device(1, "d1")
        loader = BulkDataLoader(make_fake_api())
        assert (
            _extractor(api=object(), loader=loader)._get_vrf_loopback_addresses(device)
            == []
        )

    @pytest.mark.parametrize(
        "iface_kwargs",
        [
            {"tags": ()},  # no managed tag
            {"name": "loopback0"},  # loopback0 is skipped
            {"label": "vxlan7"},  # vxlan names are skipped
            {"type": make_iface_type("1000base-t")},  # non-virtual
            {"untagged_vlan": SimpleNamespace(vid=10)},  # carries a VLAN
            {"mac_address": "aa:bb:cc:dd:ee:ff"},  # has a MAC
            {"vrf": None},  # no VRF
            {"vrf": SimpleNamespace()},  # VRF object without a name attribute
            {"vrf": make_vrf("blue")},  # VRF name does not start with "vrf"
        ],
    )
    def test_skip_guards(self, iface_kwargs):
        device = make_device(1, "d1")
        iface = _vrf_dummy(**iface_kwargs)
        loader = _loader_with(
            device, [iface], {iface.id: [make_ip("192.168.42.10/32")]}
        )
        assert (
            _extractor(api=object(), loader=loader)._get_vrf_loopback_addresses(device)
            == []
        )

    def test_qualifying_dummy_with_ipv4(self):
        device = make_device(1, "d1")
        iface = _vrf_dummy()
        loader = _loader_with(device, [iface], {20: [make_ip("192.168.42.10/32")]})
        result = _extractor(api=object(), loader=loader)._get_vrf_loopback_addresses(
            device
        )
        assert result == [{"name": "vrf42", "router_id": "192.168.42.10"}]

    def test_ipv6_only_address_is_ignored(self):
        device = make_device(1, "d1")
        iface = _vrf_dummy()
        loader = _loader_with(device, [iface], {20: [make_ip("2001:db8::1/128")]})
        result = _extractor(api=object(), loader=loader)._get_vrf_loopback_addresses(
            device
        )
        assert result == []

    def test_deduplicated_by_vrf_name(self):
        device = make_device(1, "d1")
        i1 = _vrf_dummy(id=20, name="lo-vrf-a", vrf=make_vrf("vrf42"))
        i2 = _vrf_dummy(id=21, name="lo-vrf-b", vrf=make_vrf("vrf42"))
        loader = _loader_with(
            device,
            [i1, i2],
            {20: [make_ip("192.168.42.10/32")], 21: [make_ip("192.168.42.11/32")]},
        )
        result = _extractor(api=object(), loader=loader)._get_vrf_loopback_addresses(
            device
        )
        assert result == [{"name": "vrf42", "router_id": "192.168.42.10"}]

    def test_per_interface_ip_exception_warns_and_continues(
        self, monkeypatch, mock_logger
    ):
        device = make_device(1, "d1")
        i1 = _vrf_dummy(id=20, name="lo-vrf-a", vrf=make_vrf("vrf10"))
        i2 = _vrf_dummy(id=21, name="lo-vrf-b", vrf=make_vrf("vrf20"))
        loader = _loader_with(device, [i1, i2], {21: [make_ip("192.168.42.20/32")]})

        def raiser(interface):
            if interface.id == 20:
                raise RuntimeError("boom")
            return loader.interface_ips.get(interface.id, [])

        monkeypatch.setattr(loader, "get_interface_ip_addresses", raiser)
        result = _extractor(api=object(), loader=loader)._get_vrf_loopback_addresses(
            device
        )
        assert result == [{"name": "vrf20", "router_id": "192.168.42.20"}]
        assert mock_logger.warning.called

    def test_outer_exception_returns_partial_and_errors(self, mock_logger):
        # A slug-less tag makes has_managed_tag raise AttributeError outside the
        # inner try -> the outer handler logs and returns what was collected.
        device = make_device(1, "d1")
        good = _vrf_dummy(id=20, name="lo-vrf-a", vrf=make_vrf("vrf42"))
        bad = SimpleNamespace(tags=[object()])  # .slug access raises
        loader = _loader_with(device, [good, bad], {20: [make_ip("192.168.42.10/32")]})
        result = _extractor(api=object(), loader=loader)._get_vrf_loopback_addresses(
            device
        )
        assert result == [{"name": "vrf42", "router_id": "192.168.42.10"}]
        assert mock_logger.error.called


# ---------------------------------------------------------------------------
# FRRExtractor._get_uplink_interfaces
# ---------------------------------------------------------------------------


class TestGetUplinkInterfaces:
    def test_no_api_returns_empty_and_warns(self, mock_logger):
        result = _extractor(api=None)._get_uplink_interfaces(make_device(1, "d"))
        assert result == []
        assert mock_logger.warning.called

    def test_invalid_uplinks_are_skipped(self):
        device = make_device(1, "d1")
        invalid = make_interface(id=30, label="data1", tags=())  # no managed tag
        loader = _loader_with(device, [invalid])
        assert (
            _extractor(api=object(), loader=loader)._get_uplink_interfaces(device) == []
        )

    def test_valid_uplink_with_remote_device(self):
        device = make_device(1, "d1")
        remote = make_device(2, "switch1", role=make_tag("leaf"))
        endpoint = make_interface(id=99, device=remote)
        iface = make_interface(
            id=30,
            label="data1",
            tags=("managed-by-osism",),
            connected_endpoints=[endpoint],
        )
        loader = _loader_with(device, [iface])
        result = _extractor(api=object(), loader=loader)._get_uplink_interfaces(device)
        assert result == [
            {"interface": "data1", "remote_device": remote, "interface_obj": iface}
        ]

    def test_endpoint_without_device_is_skipped(self):
        device = make_device(1, "d1")
        endpoint = SimpleNamespace()  # no .device attribute
        iface = make_interface(
            id=30,
            label="data1",
            tags=("managed-by-osism",),
            connected_endpoints=[endpoint],
        )
        loader = _loader_with(device, [iface])
        assert (
            _extractor(api=object(), loader=loader)._get_uplink_interfaces(device) == []
        )

    def test_exception_returns_partial_and_errors(self, mock_logger):
        device = make_device(1, "d1")
        remote = make_device(2, "switch1", role=make_tag("leaf"))
        good = make_interface(
            id=30,
            label="data1",
            tags=("managed-by-osism",),
            connected_endpoints=[make_interface(id=99, device=remote)],
        )
        bad = SimpleNamespace(tags=[object()])  # is_valid_uplink raises
        loader = _loader_with(device, [good, bad])
        result = _extractor(api=object(), loader=loader)._get_uplink_interfaces(device)
        assert result == [
            {"interface": "data1", "remote_device": remote, "interface_obj": good}
        ]
        assert mock_logger.error.called


# ---------------------------------------------------------------------------
# FRRExtractor._get_remote_device / _get_remote_interface
# ---------------------------------------------------------------------------


class TestGetRemoteDevice:
    def test_returns_first_endpoint_device(self):
        remote = make_device(2, "r")
        iface = make_interface(
            id=1, connected_endpoints=[SimpleNamespace(device=remote)]
        )
        assert _extractor()._get_remote_device(iface) is remote

    def test_endpoint_without_device_returns_none(self):
        iface = make_interface(id=1, connected_endpoints=[SimpleNamespace()])
        assert _extractor()._get_remote_device(iface) is None


class TestGetRemoteInterface:
    def test_missing_attr_returns_none(self):
        assert _extractor()._get_remote_interface(SimpleNamespace()) is None

    def test_empty_endpoints_returns_none(self):
        iface = make_interface(id=1, connected_endpoints=[])
        assert _extractor()._get_remote_interface(iface) is None

    def test_returns_first_endpoint(self):
        endpoint = make_interface(id=99)
        iface = make_interface(id=1, connected_endpoints=[endpoint])
        assert _extractor()._get_remote_interface(iface) is endpoint


# ---------------------------------------------------------------------------
# FRRExtractor._filter_switch_connections / _is_switch_device
# ---------------------------------------------------------------------------


class TestFilterSwitchConnections:
    def test_only_switch_uplinks_are_kept(self):
        switch = make_device(2, "sw", role=make_tag("leaf"))
        server = make_device(3, "srv", role=make_tag("compute"))
        uplinks = [
            {"remote_device": switch, "interface": "data1"},
            {"remote_device": server, "interface": "data2"},
        ]
        result = _extractor()._filter_switch_connections(uplinks, ["leaf"])
        assert result == [uplinks[0]]


class TestIsSwitchDevice:
    def test_no_role_attribute_returns_false(self):
        assert _extractor()._is_switch_device(SimpleNamespace(), ["leaf"]) is False

    def test_falsy_role_returns_false(self):
        device = make_device(1, "d", role=None)
        assert _extractor()._is_switch_device(device, ["leaf"]) is False

    def test_role_slug_in_switch_roles_returns_true(self):
        device = make_device(1, "d", role=make_tag("leaf"))
        assert _extractor()._is_switch_device(device, ["leaf"]) is True

    def test_role_slug_not_in_switch_roles_returns_false(self):
        device = make_device(1, "d", role=make_tag("spine"))
        assert _extractor()._is_switch_device(device, ["leaf"]) is False


# ---------------------------------------------------------------------------
# FRRExtractor._build_frr_uplinks
# ---------------------------------------------------------------------------


def _uplink_setup(
    *,
    local_device,
    full_remote,
    endpoint_custom_fields=None,
    local_custom_fields=None,
):
    """Wire a single local uplink (data1) to one switch remote.

    The connected endpoint doubles as the remote interface: it carries
    ``.device`` (a minimal switch with role "leaf") for remote-device
    resolution and ``.custom_fields`` for the frr_local_pref lookup. The full
    remote (with custom fields / config_context) is returned by dcim.devices.get.
    """
    endpoint = make_interface(
        id=99,
        device=make_device(2, "leaf1", role=make_tag("leaf")),
        custom_fields=endpoint_custom_fields or {},
    )
    local_uplink = make_interface(
        id=30,
        label="data1",
        tags=("managed-by-osism",),
        connected_endpoints=[endpoint],
        custom_fields=local_custom_fields or {},
    )
    loader = _loader_with(local_device, [local_uplink])
    api = make_fake_api(devices_by_id={2: full_remote})
    return _extractor(api=api, loader=loader)


class TestBuildFrrUplinks:
    def test_no_switch_uplinks_returns_empty(self):
        device = make_device(1, "d1")
        remote = make_device(2, "srv", role=make_tag("compute"))  # not a switch
        endpoint = make_interface(id=99, device=remote)
        iface = make_interface(
            id=30,
            label="data1",
            tags=("managed-by-osism",),
            connected_endpoints=[endpoint],
        )
        loader = _loader_with(device, [iface])
        ex = _extractor(api=make_fake_api(), loader=loader)
        assert ex._build_frr_uplinks(device, ["leaf"], 4200) == []

    def test_resolvable_remote_as_via_devices_get(self):
        # Only the full remote (fetched via dcim.devices.get) carries the AS, so a
        # result proves the fetch happened.
        local = make_device(1, "spine1")
        full_remote = make_device(
            2, "leaf1", role=make_tag("leaf"), custom_fields={"frr_local_as": 64600}
        )
        ex = _uplink_setup(local_device=local, full_remote=full_remote)
        assert ex._build_frr_uplinks(local, ["leaf"], 4200) == [
            {"interface": "data1", "remote_as": 64600}
        ]

    def test_devices_get_raising_falls_back_and_warns(self, mock_logger):
        local = make_device(1, "spine1")
        remote = make_device(
            2, "leaf1", role=make_tag("leaf"), custom_fields={"frr_local_as": 64700}
        )
        endpoint = make_interface(id=99, device=remote)
        local_uplink = make_interface(
            id=30,
            label="data1",
            tags=("managed-by-osism",),
            connected_endpoints=[endpoint],
        )
        loader = _loader_with(local, [local_uplink])
        api = MagicMock()
        api.dcim.devices.get.side_effect = RuntimeError("boom")
        api.dcim.interfaces.filter.return_value = []  # remote loopback0 fallback
        ex = _extractor(api=api, loader=loader)
        # Falls back to the minimal remote object, which still carries the AS.
        assert ex._build_frr_uplinks(local, ["leaf"], 4200) == [
            {"interface": "data1", "remote_as": 64700}
        ]
        assert mock_logger.warning.called

    def test_yrzn_local_emits_uplink_without_remote_as(self):
        local = make_device(
            1, "spine1", config_context={"frr_parameters": {"frr_type": "yrzn-spine"}}
        )
        full_remote = make_device(2, "leaf1", role=make_tag("leaf"), custom_fields={})
        ex = _uplink_setup(local_device=local, full_remote=full_remote)
        # Remote AS unresolvable, but the yrzn local still emits the uplink.
        assert ex._build_frr_uplinks(local, ["leaf"], 4200) == [{"interface": "data1"}]

    def test_yrzn_remote_drops_uplink_silently(self, mock_logger):
        local = make_device(1, "leaf1")  # not yrzn
        full_remote = make_device(
            2,
            "spine1",
            role=make_tag("leaf"),
            config_context={"frr_parameters": {"frr_type": "yrzn-spine"}},
            custom_fields={},
        )
        ex = _uplink_setup(local_device=local, full_remote=full_remote)
        assert ex._build_frr_uplinks(local, ["leaf"], 4200) == []
        assert not mock_logger.warning.called

    def test_neither_yrzn_nor_remote_as_drops_with_warning(self, mock_logger):
        local = make_device(1, "leaf1")
        full_remote = make_device(2, "spine1", role=make_tag("leaf"), custom_fields={})
        ex = _uplink_setup(local_device=local, full_remote=full_remote)
        assert ex._build_frr_uplinks(local, ["leaf"], 4200) == []
        assert mock_logger.warning.called

    def test_local_pref_local_only(self):
        local = make_device(1, "spine1")
        full_remote = make_device(
            2, "leaf1", role=make_tag("leaf"), custom_fields={"frr_local_as": 64600}
        )
        ex = _uplink_setup(
            local_device=local,
            full_remote=full_remote,
            local_custom_fields={"frr_local_pref": 200},
        )
        assert ex._build_frr_uplinks(local, ["leaf"], 4200) == [
            {"interface": "data1", "remote_as": 64600, "local_pref": 200}
        ]

    def test_local_pref_remote_only(self):
        local = make_device(1, "spine1")
        full_remote = make_device(
            2, "leaf1", role=make_tag("leaf"), custom_fields={"frr_local_as": 64600}
        )
        ex = _uplink_setup(
            local_device=local,
            full_remote=full_remote,
            endpoint_custom_fields={"frr_local_pref": 150},
        )
        assert ex._build_frr_uplinks(local, ["leaf"], 4200) == [
            {"interface": "data1", "remote_as": 64600, "local_pref": 150}
        ]

    def test_local_pref_both_uses_max_and_debug_logs(self, mock_logger):
        local = make_device(1, "spine1")
        full_remote = make_device(
            2, "leaf1", role=make_tag("leaf"), custom_fields={"frr_local_as": 64600}
        )
        ex = _uplink_setup(
            local_device=local,
            full_remote=full_remote,
            local_custom_fields={"frr_local_pref": 200},
            endpoint_custom_fields={"frr_local_pref": 150},
        )
        result = ex._build_frr_uplinks(local, ["leaf"], 4200)
        assert result == [{"interface": "data1", "remote_as": 64600, "local_pref": 200}]
        assert any(
            "frr_local_pref" in str(call) for call in mock_logger.debug.call_args_list
        )

    def test_local_pref_neither_omits_key(self):
        local = make_device(1, "spine1")
        full_remote = make_device(
            2, "leaf1", role=make_tag("leaf"), custom_fields={"frr_local_as": 64600}
        )
        ex = _uplink_setup(local_device=local, full_remote=full_remote)
        result = ex._build_frr_uplinks(local, ["leaf"], 4200)
        assert result == [{"interface": "data1", "remote_as": 64600}]


# ---------------------------------------------------------------------------
# FRRExtractor.extract
# ---------------------------------------------------------------------------


class TestExtract:
    def test_no_api_returns_none(self):
        assert _extractor(api=None).extract(make_device(1, "d1")) is None

    def test_loopback0_ipv4_yields_loopback_and_local_as(self):
        device = make_device(1, "d1", custom_fields={})
        lo = make_interface(id=10, name="loopback0")
        loader = _loader_with(device, [lo], {10: [make_ip("192.168.45.123/32")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["frr_loopback_v4"] == "192.168.45.123"  # mask stripped
        assert result["frr_local_as"] == 4200045123

    def test_loopback0_ipv6_yields_loopback_v6(self):
        device = make_device(1, "d1", custom_fields={})
        lo = make_interface(id=10, name="loopback0")
        loader = _loader_with(device, [lo], {10: [make_ip("2001:db8::1/128")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["frr_loopback_v6"] == "2001:db8::1"
        assert "frr_loopback_v4" not in result

    def test_uplinks_yield_groups_by_label_prefix(self):
        device = make_device(1, "spine1")
        fr1 = make_device(
            2, "leaf1", role=make_tag("leaf"), custom_fields={"frr_local_as": 64601}
        )
        fr2 = make_device(
            3, "leaf2", role=make_tag("leaf"), custom_fields={"frr_local_as": 64602}
        )
        ep1 = make_interface(
            id=101, device=make_device(2, "leaf1", role=make_tag("leaf"))
        )
        ep2 = make_interface(
            id=102, device=make_device(3, "leaf2", role=make_tag("leaf"))
        )
        up1 = make_interface(
            id=30, label="data1", tags=("managed-by-osism",), connected_endpoints=[ep1]
        )
        up2 = make_interface(
            id=31, label="data2", tags=("managed-by-osism",), connected_endpoints=[ep2]
        )
        loader = _loader_with(device, [up1, up2])
        api = make_fake_api(devices_by_id={2: fr1, 3: fr2})
        result = _extractor(api=api, loader=loader).extract(device)
        expected = [
            {"interface": "data1", "remote_as": 64601},
            {"interface": "data2", "remote_as": 64602},
        ]
        assert result["frr_uplinks"] == expected
        assert result["frr_uplinks_data"] == expected

    def test_switch_roles_none_falls_back_to_default(self):
        # "leaf" is in DEFAULT_FRR_SWITCH_ROLES, so the uplink is still matched
        # when switch_roles is not passed.
        device = make_device(1, "spine1")
        fr = make_device(
            2, "leaf1", role=make_tag("leaf"), custom_fields={"frr_local_as": 64601}
        )
        ep = make_interface(
            id=101, device=make_device(2, "leaf1", role=make_tag("leaf"))
        )
        up = make_interface(
            id=30, label="data1", tags=("managed-by-osism",), connected_endpoints=[ep]
        )
        loader = _loader_with(device, [up])
        api = make_fake_api(devices_by_id={2: fr})
        result = _extractor(api=api, loader=loader).extract(device)
        assert result["frr_uplinks"] == [{"interface": "data1", "remote_as": 64601}]

    def test_vrf_loopbacks_yield_frr_vrfs(self):
        device = make_device(1, "d1")
        vrf_iface = _vrf_dummy(id=40, name="lo-vrf-a", vrf=make_vrf("vrf42"))
        loader = _loader_with(device, [vrf_iface], {40: [make_ip("192.168.42.10/32")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["frr_vrfs"] == [{"name": "vrf42", "router_id": "192.168.42.10"}]

    def test_config_context_only_default_is_emitted_and_written(self):
        # No loopback0 and no uplinks, so interface auto-generation yields
        # nothing - but config_context carries an frr_parameters default. Since
        # ConfigContextExtractor strips frr_parameters from the generic
        # config-context output, this extractor is its only emission surface and
        # must still emit (and cache) it rather than dropping it via an
        # emptiness check that runs before the merge.
        device = make_device(
            1,
            "d1",
            config_context={"frr_parameters": {"frr_loopback_v4": "1.2.3.4"}},
        )
        client = MagicMock()
        client.update_device_custom_field.return_value = True
        ex = _extractor(api=object(), netbox_client=client)
        result = ex.extract(device)
        assert result == {"frr_loopback_v4": "1.2.3.4"}
        client.update_device_custom_field.assert_called_once_with(
            device, "frr_parameters", result
        )

    def test_nothing_found_and_no_config_context_returns_none_no_write(self):
        # Truly empty: no generated parameters and no config_context default.
        device = make_device(1, "d1", config_context=None)
        client = MagicMock()
        ex = _extractor(api=object(), netbox_client=client)
        assert ex.extract(device) is None
        client.update_device_custom_field.assert_not_called()

    def test_config_context_overrides_are_deep_merged(self, mock_logger):
        device = make_device(
            1,
            "d1",
            custom_fields={},
            config_context={
                "frr_parameters": {"frr_loopback_v4": "9.9.9.9", "extra_key": "x"}
            },
        )
        lo = make_interface(id=10, name="loopback0")
        loader = _loader_with(device, [lo], {10: [make_ip("192.168.45.123/32")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["frr_loopback_v4"] == "9.9.9.9"  # override wins
        assert result["frr_local_as"] == 4200045123  # untouched auto key survives
        assert result["extra_key"] == "x"  # new key from config_context
        assert mock_logger.info.called

    def test_netbox_client_write_called_once(self):
        device = make_device(1, "d1", custom_fields={})
        lo = make_interface(id=10, name="loopback0")
        loader = _loader_with(device, [lo], {10: [make_ip("192.168.45.123/32")]})
        client = MagicMock()
        client.update_device_custom_field.return_value = True
        result = _extractor(api=object(), netbox_client=client, loader=loader).extract(
            device
        )
        client.update_device_custom_field.assert_called_once_with(
            device, "frr_parameters", result
        )

    def test_netbox_client_falsy_return_warns(self, mock_logger):
        device = make_device(1, "d1", custom_fields={})
        lo = make_interface(id=10, name="loopback0")
        loader = _loader_with(device, [lo], {10: [make_ip("192.168.45.123/32")]})
        client = MagicMock()
        client.update_device_custom_field.return_value = False
        _extractor(api=object(), netbox_client=client, loader=loader).extract(device)
        assert mock_logger.warning.called

    def test_netbox_client_none_no_write(self):
        device = make_device(1, "d1", custom_fields={})
        lo = make_interface(id=10, name="loopback0")
        loader = _loader_with(device, [lo], {10: [make_ip("192.168.45.123/32")]})
        result = _extractor(api=object(), netbox_client=None, loader=loader).extract(
            device
        )
        assert result["frr_loopback_v4"] == "192.168.45.123"


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
