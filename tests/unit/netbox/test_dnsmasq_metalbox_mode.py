# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/dnsmasq/metalbox_mode.py.

``MetalboxModeHandler`` builds the metalbox OOB dnsmasq configuration in two
sub-modes (bridged / routed). This file covers, in two parts:

* Part 1 -- the pure and single-interface helpers (``_build_prefix_tag_mapping``,
  ``_index_to_suffix``, ``_get_set_tag_for_ip``,
  ``_get_metalbox_oob_virtual_interface``, ``_get_ipv4_from_interface``,
  ``_get_physical_uplink_interfaces``, ``_get_dhcp_options_routed``,
  ``_get_dynamic_hosts_routed``).
* Part 2 -- the collectors (``get_dynamic_hosts_for_metalbox``,
  ``get_dhcp_options_for_metalbox``) and the ``process_devices`` orchestrator
  (bridged / routed / switch-tracking scenarios).

Interfaces / IP addresses / prefixes are read through a pynetbox session faked
by ``make_fake_api`` (plain lists) or a ``MagicMock`` where ``side_effect``
matters; the higher-level ``netbox_client`` façade methods
(``get_oob_networks``, ``get_all_oob_prefixes``, ``get_device_oob_interface``,
``update_device_custom_field``) are stubbed per scenario. The module-level
``loguru`` logger is patched only where a log assertion documents the branch.
"""

import ipaddress
from unittest.mock import MagicMock

import pytest

from dnsmasq.dhcp_config import DHCPConfigGenerator
from dnsmasq.interface_handler import InterfaceHandler
from dnsmasq.metalbox_mode import MetalboxModeHandler

from .conftest import (
    make_device,
    make_dnsmasq_config,
    make_fake_api,
    make_iface_type,
    make_interface,
    make_ip,
    make_prefix,
    make_vlan,
)


@pytest.fixture
def mock_logger(monkeypatch):
    """Replace the module-level loguru logger with a MagicMock."""
    logger = MagicMock()
    monkeypatch.setattr("dnsmasq.metalbox_mode.logger", logger)
    return logger


def _handler(tmp_path, **overrides):
    return MetalboxModeHandler(make_dnsmasq_config(tmp_path, **overrides))


def _client(interfaces=(), ips_by_interface=None, *, oob_prefixes=(), prefixes=()):
    """Fake NetBoxClient: a MagicMock with a make_fake_api .api."""
    client = MagicMock()
    client.api = make_fake_api(
        interfaces=interfaces,
        ips_by_interface=ips_by_interface or {},
        prefixes=prefixes,
    )
    client.get_all_oob_prefixes.return_value = list(oob_prefixes)
    return client


def _virtual(**overrides):
    params = dict(type=make_iface_type("virtual"))
    params.update(overrides)
    return make_interface(**params)


# ===========================================================================
# Part 1 -- pure & single-interface helpers
# ===========================================================================


class TestInit:
    def test_constructs_collaborators(self, tmp_path):
        config = make_dnsmasq_config(tmp_path)
        handler = MetalboxModeHandler(config)
        assert handler.config is config
        assert isinstance(handler.dhcp_generator, DHCPConfigGenerator)
        assert isinstance(handler.interface_handler, InterfaceHandler)


class TestBuildPrefixTagMapping:
    def test_ipv6_prefixes_dropped(self, tmp_path):
        handler = _handler(tmp_path)
        mapping = handler._build_prefix_tag_mapping(
            [
                make_prefix("192.0.2.0/24", vlan=make_vlan(100)),
                make_prefix("2001:db8::/64", vlan=make_vlan(200)),
            ]
        )
        assert "2001:db8::/64" not in mapping
        assert mapping["192.0.2.0/24"]["tag"] == "vlan100"

    def test_unique_vlan_and_no_vlan_tags(self, tmp_path):
        handler = _handler(tmp_path)
        mapping = handler._build_prefix_tag_mapping(
            [
                make_prefix("192.0.2.0/24", vlan=make_vlan(100)),
                make_prefix("198.51.100.0/24"),
            ]
        )
        assert mapping["192.0.2.0/24"]["tag"] == "vlan100"
        assert mapping["198.51.100.0/24"]["tag"] == "oob"

    def test_duplicate_vlan_ids_get_sorted_suffixes(self, tmp_path):
        handler = _handler(tmp_path)
        mapping = handler._build_prefix_tag_mapping(
            [
                make_prefix("198.51.100.0/24", vlan=make_vlan(100)),
                make_prefix("192.0.2.0/24", vlan=make_vlan(100)),
            ]
        )
        # Suffixes follow network-address order, independent of input order.
        assert mapping["192.0.2.0/24"]["tag"] == "vlan100a"
        assert mapping["198.51.100.0/24"]["tag"] == "vlan100b"

    def test_duplicate_no_vlan_prefixes_get_oob_suffixes(self, tmp_path):
        handler = _handler(tmp_path)
        mapping = handler._build_prefix_tag_mapping(
            [make_prefix("198.51.100.0/24"), make_prefix("192.0.2.0/24")]
        )
        assert mapping["192.0.2.0/24"]["tag"] == "ooba"
        assert mapping["198.51.100.0/24"]["tag"] == "oobb"

    def test_suffix_assignment_is_deterministic_under_shuffle(self, tmp_path):
        handler = _handler(tmp_path)
        prefixes = [
            make_prefix("203.0.113.0/24", vlan=make_vlan(100)),
            make_prefix("192.0.2.0/24", vlan=make_vlan(100)),
            make_prefix("198.51.100.0/24", vlan=make_vlan(100)),
        ]
        mapping = handler._build_prefix_tag_mapping(prefixes)
        assert mapping["192.0.2.0/24"]["tag"] == "vlan100a"
        assert mapping["198.51.100.0/24"]["tag"] == "vlan100b"
        assert mapping["203.0.113.0/24"]["tag"] == "vlan100c"

    def test_return_shape(self, tmp_path):
        handler = _handler(tmp_path)
        mapping = handler._build_prefix_tag_mapping(
            [make_prefix("192.0.2.0/24", vlan=make_vlan(100))]
        )
        assert mapping["192.0.2.0/24"] == {
            "tag": "vlan100",
            "network": ipaddress.ip_network("192.0.2.0/24"),
            "vlan_id": 100,
        }


class TestIndexToSuffix:
    @pytest.mark.parametrize(
        "idx,expected",
        [
            (0, "a"),
            (25, "z"),
            (26, "aa"),
            (27, "ab"),
            (51, "az"),
            (52, "ba"),
            (701, "zz"),
        ],
    )
    def test_index_to_suffix(self, idx, expected):
        assert MetalboxModeHandler._index_to_suffix(idx) == expected


class TestGetSetTagForIp:
    def _mapping(self, tmp_path):
        return _handler(tmp_path)._build_prefix_tag_mapping(
            [make_prefix("192.0.2.0/24", vlan=make_vlan(100))]
        )

    def test_ip_inside_mapped_network(self, tmp_path):
        handler = _handler(tmp_path)
        assert (
            handler._get_set_tag_for_ip("192.0.2.10", self._mapping(tmp_path))
            == "vlan100"
        )

    def test_ip_outside_all_networks(self, tmp_path):
        handler = _handler(tmp_path)
        assert handler._get_set_tag_for_ip("10.0.0.1", self._mapping(tmp_path)) is None

    def test_ip_with_prefix_suffix_is_stripped(self, tmp_path):
        handler = _handler(tmp_path)
        assert (
            handler._get_set_tag_for_ip("192.0.2.10/24", self._mapping(tmp_path))
            == "vlan100"
        )


class TestGetMetalboxOobVirtualInterface:
    def test_priority1_loopback0_with_ipv4(self, tmp_path):
        handler = _handler(tmp_path)
        lb = make_interface(id=1, name="loopback0", type=make_iface_type("virtual"))
        client = _client([lb], {1: [make_ip("192.0.2.5/24")]})

        result = handler._get_metalbox_oob_virtual_interface(
            make_device(1, "metalbox"), client
        )

        assert result == ("192.0.2.5", "loopback0")

    def test_priority2_single_virtual_prefers_label(self, tmp_path, mock_logger):
        handler = _handler(tmp_path)
        v = _virtual(id=2, name="oob0", label="oob-label")
        client = _client([v], {2: [make_ip("192.0.2.6/24")]})

        result = handler._get_metalbox_oob_virtual_interface(
            make_device(1, "metalbox"), client
        )

        assert result == ("192.0.2.6", "oob-label")
        mock_logger.info.assert_called_once()

    def test_priority3_out_of_band_tagged_interface(self, tmp_path, mock_logger):
        handler = _handler(tmp_path)
        v1 = _virtual(id=3, name="v1", tags=())
        v2 = _virtual(id=4, name="v2", label="oob2", tags=("out-of-band",))
        client = _client([v1, v2], {4: [make_ip("192.0.2.7/24")]})

        result = handler._get_metalbox_oob_virtual_interface(
            make_device(1, "metalbox"), client
        )

        assert result == ("192.0.2.7", "oob2")
        mock_logger.info.assert_called_once()

    def test_multiple_virtual_none_out_of_band_warns(self, tmp_path, mock_logger):
        handler = _handler(tmp_path)
        v1 = _virtual(id=3, name="v1", tags=())
        v2 = _virtual(id=4, name="v2", tags=("other",))
        client = _client([v1, v2])

        result = handler._get_metalbox_oob_virtual_interface(
            make_device(1, "metalbox"), client
        )

        assert result == (None, None)
        mock_logger.warning.assert_called_once()

    def test_loopback0_without_ipv4_falls_through(self, tmp_path):
        handler = _handler(tmp_path)
        # loopback0 is non-virtual and has no IP -> P1 misses, falls to P2.
        lb = make_interface(id=1, name="loopback0", type=make_iface_type("1000base-t"))
        v = _virtual(id=2, name="oob0", label="oob-label")
        client = _client([lb, v], {2: [make_ip("192.0.2.8/24")]})

        result = handler._get_metalbox_oob_virtual_interface(
            make_device(1, "metalbox"), client
        )

        assert result == ("192.0.2.8", "oob-label")

    def test_nothing_resolvable(self, tmp_path):
        handler = _handler(tmp_path)
        client = _client([])

        result = handler._get_metalbox_oob_virtual_interface(
            make_device(1, "metalbox"), client
        )

        assert result == (None, None)


class TestGetIpv4FromInterface:
    def test_single_ipv4_returned_without_prefix(self, tmp_path):
        handler = _handler(tmp_path)
        iface = make_interface(id=5)
        client = _client([], {5: [make_ip("192.0.2.7/24")]})
        assert handler._get_ipv4_from_interface(iface, client) == "192.0.2.7"

    def test_only_ipv6_returns_none(self, tmp_path):
        handler = _handler(tmp_path)
        iface = make_interface(id=5)
        client = _client([], {5: [make_ip("2001:db8::1/64")]})
        assert handler._get_ipv4_from_interface(iface, client) is None

    def test_no_addresses_returns_none(self, tmp_path):
        handler = _handler(tmp_path)
        iface = make_interface(id=5)
        client = _client([], {5: []})
        assert handler._get_ipv4_from_interface(iface, client) is None

    def test_multiple_ipv4_prefers_oob_role_prefix(self, tmp_path):
        handler = _handler(tmp_path)
        iface = make_interface(id=5)
        client = _client(
            [],
            {5: [make_ip("10.0.0.1/24"), make_ip("192.0.2.8/24")]},
            oob_prefixes=[make_prefix("192.0.2.0/24")],
        )
        assert handler._get_ipv4_from_interface(iface, client) == "192.0.2.8"

    def test_multiple_ipv4_none_in_oob_prefix_falls_back_to_first(self, tmp_path):
        handler = _handler(tmp_path)
        iface = make_interface(id=5)
        client = _client(
            [],
            {5: [make_ip("10.0.0.1/24"), make_ip("192.0.2.8/24")]},
            oob_prefixes=[make_prefix("203.0.113.0/24")],
        )
        assert handler._get_ipv4_from_interface(iface, client) == "10.0.0.1"


class TestGetPhysicalUplinkInterfaces:
    def _uplink(self, **overrides):
        params = dict(
            id=1,
            tags=("managed-by-osism", "out-of-band"),
            label="up0",
            connected_endpoints=[object()],
            enabled=True,
            mgmt_only=False,
        )
        params.update(overrides)
        return make_interface(**params)

    def test_qualifying_interface_label_collected(self, tmp_path):
        handler = _handler(tmp_path)
        client = _client([self._uplink()])
        result = handler._get_physical_uplink_interfaces(
            make_device(1, "metalbox"), client
        )
        assert result == ["up0"]

    def test_missing_required_tag_skipped(self, tmp_path):
        handler = _handler(tmp_path)
        client = _client([self._uplink(tags=("managed-by-osism",))])
        assert (
            handler._get_physical_uplink_interfaces(make_device(1, "m"), client) == []
        )

    def test_missing_label_skipped(self, tmp_path):
        handler = _handler(tmp_path)
        client = _client([self._uplink(label=None)])
        assert (
            handler._get_physical_uplink_interfaces(make_device(1, "m"), client) == []
        )

    def test_no_connected_endpoints_skipped(self, tmp_path):
        handler = _handler(tmp_path)
        client = _client([self._uplink(connected_endpoints=None)])
        assert (
            handler._get_physical_uplink_interfaces(make_device(1, "m"), client) == []
        )

    def test_disabled_skipped(self, tmp_path):
        handler = _handler(tmp_path)
        client = _client([self._uplink(enabled=False)])
        assert (
            handler._get_physical_uplink_interfaces(make_device(1, "m"), client) == []
        )

    def test_mgmt_only_skipped(self, tmp_path):
        handler = _handler(tmp_path)
        client = _client([self._uplink(mgmt_only=True)])
        assert (
            handler._get_physical_uplink_interfaces(make_device(1, "m"), client) == []
        )

    def test_filter_raises_warns_and_returns_collected(self, tmp_path, mock_logger):
        handler = _handler(tmp_path)
        client = MagicMock()
        client.api.dcim.interfaces.filter.side_effect = Exception("boom")

        result = handler._get_physical_uplink_interfaces(
            make_device(1, "metalbox"), client
        )

        assert result == []
        mock_logger.warning.assert_called_once()


class TestGetDhcpOptionsRouted:
    def test_three_options_per_prefix_with_gateway(self, tmp_path):
        handler = _handler(tmp_path)
        mapping = handler._build_prefix_tag_mapping(
            [make_prefix("192.0.2.0/24", vlan=make_vlan(100))]
        )
        options = handler._get_dhcp_options_routed("192.0.2.254", mapping)
        assert options == [
            "tag:vlan100,3,192.0.2.1",
            "tag:vlan100,6,192.0.2.254",
            "tag:vlan100,42,192.0.2.254",
        ]


class TestGetDynamicHostsRouted:
    def test_exact_two_entries(self, tmp_path):
        handler = _handler(tmp_path)
        assert handler._get_dynamic_hosts_routed("192.0.2.254", "oob0") == [
            "metalbox,192.0.2.254,oob0",
            "metalbox.osism.xyz,192.0.2.254,oob0",
        ]
