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
from types import SimpleNamespace
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
    make_tag,
    make_vlan,
    make_vlan_group,
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


# ===========================================================================
# Part 2 -- collectors & process_devices
# ===========================================================================


class TestGetDynamicHostsForMetalbox:
    def test_no_oob_networks_returns_empty(self, tmp_path):
        handler = _handler(tmp_path)
        client = _client([])
        client.get_oob_networks.return_value = []
        assert handler.get_dynamic_hosts_for_metalbox(make_device(1, "m"), client) == []

    def test_filter_raises_warns_and_returns_empty(self, tmp_path, mock_logger):
        handler = _handler(tmp_path)
        client = MagicMock()
        client.get_oob_networks.return_value = [
            make_prefix("192.0.2.0/24", vlan=make_vlan(100))
        ]
        client.api.dcim.interfaces.filter.side_effect = Exception("boom")

        assert handler.get_dynamic_hosts_for_metalbox(make_device(1, "m"), client) == []
        mock_logger.warning.assert_called_once()

    def test_matching_network_and_interface_emits_both_entries(self, tmp_path):
        handler = _handler(tmp_path)
        iface = _virtual(
            id=1, name="oob0", label="oob-vlan", untagged_vlan=make_vlan(100)
        )
        client = _client([iface], {1: [make_ip("192.0.2.10/24")]})
        client.get_oob_networks.return_value = [
            make_prefix("192.0.2.0/24", vlan=make_vlan(100))
        ]

        result = handler.get_dynamic_hosts_for_metalbox(
            make_device(2, "metalbox"), client
        )

        assert result == [
            "metalbox,192.0.2.10,oob-vlan",
            "metalbox.osism.xyz,192.0.2.10,oob-vlan",
        ]

    def test_breaks_on_first_matching_ip(self, tmp_path):
        handler = _handler(tmp_path)
        iface = _virtual(
            id=1, name="oob0", label="oob-vlan", untagged_vlan=make_vlan(100)
        )
        client = _client(
            [iface],
            {1: [make_ip("192.0.2.10/24"), make_ip("192.0.2.11/24")]},
        )
        client.get_oob_networks.return_value = [
            make_prefix("192.0.2.0/24", vlan=make_vlan(100))
        ]

        result = handler.get_dynamic_hosts_for_metalbox(
            make_device(2, "metalbox"), client
        )

        assert result == [
            "metalbox,192.0.2.10,oob-vlan",
            "metalbox.osism.xyz,192.0.2.10,oob-vlan",
        ]

    def test_network_without_vlan_contributes_nothing(self, tmp_path):
        handler = _handler(tmp_path)
        iface = _virtual(id=1, label="oob-vlan", untagged_vlan=make_vlan(100))
        client = _client([iface], {1: [make_ip("192.0.2.10/24")]})
        client.get_oob_networks.return_value = [make_prefix("192.0.2.0/24")]

        assert handler.get_dynamic_hosts_for_metalbox(make_device(2, "m"), client) == []

    def test_vlan_without_matching_interface_contributes_nothing(self, tmp_path):
        handler = _handler(tmp_path)
        iface = _virtual(id=1, label="oob-vlan", untagged_vlan=make_vlan(100))
        client = _client([iface], {1: [make_ip("192.0.2.10/24")]})
        client.get_oob_networks.return_value = [
            make_prefix("192.0.2.0/24", vlan=make_vlan(200))
        ]

        assert handler.get_dynamic_hosts_for_metalbox(make_device(2, "m"), client) == []


class TestGetDhcpOptionsForMetalbox:
    def test_filter_raises_warns_and_returns_empty(self, tmp_path, mock_logger):
        handler = _handler(tmp_path)
        client = MagicMock()
        client.api.dcim.interfaces.filter.side_effect = Exception("boom")

        assert handler.get_dhcp_options_for_metalbox(make_device(1, "m"), client) == []
        mock_logger.warning.assert_called_once()

    def test_managed_vlan_emits_dns_and_ntp_options(self, tmp_path):
        handler = _handler(tmp_path)
        iface = _virtual(
            id=1, name="oob0", tags=("managed-by-osism",), untagged_vlan=make_vlan(100)
        )
        client = _client(
            [iface],
            {1: [make_ip("192.0.2.10/24")]},
            prefixes=[make_prefix("192.0.2.0/24", vlan=make_vlan(100))],
        )

        result = handler.get_dhcp_options_for_metalbox(
            make_device(2, "metalbox"), client
        )

        assert result == [
            "tag:vlan100,6,192.0.2.10",
            "tag:vlan100,42,192.0.2.10",
        ]
        # Pin the managed-by-osism prefix filter: the fake ignores the argument,
        # so record it here to catch a regression that drops the tag filter.
        assert client.api.ipam.prefixes.filter_calls == [["managed-by-osism"]]

    def test_vlan_not_in_managed_set_is_skipped(self, tmp_path):
        handler = _handler(tmp_path)
        iface = _virtual(
            id=1, name="oob0", tags=("managed-by-osism",), untagged_vlan=make_vlan(200)
        )
        client = _client(
            [iface],
            {1: [make_ip("192.0.2.10/24")]},
            prefixes=[make_prefix("192.0.2.0/24", vlan=make_vlan(100))],
        )

        assert handler.get_dhcp_options_for_metalbox(make_device(2, "m"), client) == []

    def test_prefixes_filter_raises_disables_managed_filter(
        self, tmp_path, mock_logger
    ):
        handler = _handler(tmp_path)
        iface = _virtual(
            id=1, name="oob0", tags=("managed-by-osism",), untagged_vlan=make_vlan(100)
        )
        client = MagicMock()
        client.api.dcim.interfaces.filter.return_value = [iface]
        client.api.ipam.prefixes.filter.side_effect = Exception("boom")
        client.api.ipam.ip_addresses.filter.return_value = [make_ip("192.0.2.10/24")]

        result = handler.get_dhcp_options_for_metalbox(
            make_device(2, "metalbox"), client
        )

        # managed_vlan_ids falls back to None, so the VLAN filter is disabled.
        assert result == [
            "tag:vlan100,6,192.0.2.10",
            "tag:vlan100,42,192.0.2.10",
        ]
        mock_logger.warning.assert_called_once()

    def test_routed_vlan_group_adds_gateway_option(self, tmp_path):
        handler = _handler(tmp_path)
        iface = _virtual(
            id=1,
            name="oob0",
            tags=("managed-by-osism",),
            untagged_vlan=make_vlan(100, group=make_vlan_group("routed-oob")),
        )
        client = _client(
            [iface],
            {1: [make_ip("192.0.2.10/24")]},
            prefixes=[make_prefix("192.0.2.0/24", vlan=make_vlan(100))],
        )

        result = handler.get_dhcp_options_for_metalbox(
            make_device(2, "metalbox"), client
        )

        assert result == [
            "tag:vlan100,6,192.0.2.10",
            "tag:vlan100,42,192.0.2.10",
            "tag:vlan100,3,192.0.2.1",
        ]

    def test_only_first_ip_per_interface_is_used(self, tmp_path):
        handler = _handler(tmp_path)
        iface = _virtual(
            id=1, name="oob0", tags=("managed-by-osism",), untagged_vlan=make_vlan(100)
        )
        client = _client(
            [iface],
            {1: [make_ip("192.0.2.10/24"), make_ip("192.0.2.11/24")]},
            prefixes=[make_prefix("192.0.2.0/24", vlan=make_vlan(100))],
        )

        result = handler.get_dhcp_options_for_metalbox(
            make_device(2, "metalbox"), client
        )

        assert result == [
            "tag:vlan100,6,192.0.2.10",
            "tag:vlan100,42,192.0.2.10",
        ]

    def test_gateway_calc_exception_warns(self, tmp_path, mock_logger):
        handler = _handler(tmp_path)
        iface = _virtual(
            id=1,
            name="oob0",
            tags=("managed-by-osism",),
            untagged_vlan=make_vlan(100, group=make_vlan_group("routed")),
        )
        client = _client(
            [iface],
            {1: [make_ip("192.0.2.999/24")]},  # malformed -> gateway calc raises
            prefixes=[make_prefix("192.0.2.0/24", vlan=make_vlan(100))],
        )

        result = handler.get_dhcp_options_for_metalbox(
            make_device(2, "metalbox"), client
        )

        # Characterization of existing behavior, NOT intended validation: only
        # option 3 (gateway) is guarded by ``ip_network()``, so the malformed
        # 192.0.2.999 is dropped there. Options 6 and 42 come from the
        # unvalidated ``split("/")[0]`` and leak the bad address straight
        # through -- a future reader should not mistake this for "invalid IPs
        # are rejected".
        assert result == [
            "tag:vlan100,6,192.0.2.999",
            "tag:vlan100,42,192.0.2.999",
        ]
        mock_logger.warning.assert_called_once()

    def test_no_interfaces_returns_empty(self, tmp_path):
        handler = _handler(tmp_path)
        assert (
            handler.get_dhcp_options_for_metalbox(make_device(1, "m"), _client([]))
            == []
        )

    @pytest.mark.parametrize(
        "iface",
        [
            # non-virtual
            _virtual(
                id=1,
                type=make_iface_type("1000base-t"),
                tags=("managed-by-osism",),
                untagged_vlan=make_vlan(100),
            ),
            # no tags
            _virtual(id=1, tags=(), untagged_vlan=make_vlan(100)),
            # tags without managed-by-osism
            _virtual(id=1, tags=("other",), untagged_vlan=make_vlan(100)),
            # no untagged VLAN
            _virtual(id=1, tags=("managed-by-osism",), untagged_vlan=None),
        ],
    )
    def test_non_qualifying_interfaces_skipped(self, tmp_path, iface):
        handler = _handler(tmp_path)
        client = _client(
            [iface],
            {1: [make_ip("192.0.2.10/24")]},
            prefixes=[make_prefix("192.0.2.0/24", vlan=make_vlan(100))],
        )
        assert handler.get_dhcp_options_for_metalbox(make_device(2, "m"), client) == []


def _oob(mapping):
    """A get_device_oob_interface side_effect keyed by device.id."""
    return lambda device: mapping[device.id]


class TestProcessDevices:
    def test_no_metalbox_device_early_returns(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, reconciler_mode="metalbox")
        monkeypatch.setattr(handler, "write_dnsmasq_to_device", MagicMock())
        client = MagicMock()
        devices = [make_device(1, "node1", role=make_tag("compute"))]

        handler.process_devices(client, devices, devices)

        handler.write_dnsmasq_to_device.assert_not_called()
        client.get_device_oob_interface.assert_not_called()

    def test_bridged_writes_five_metalbox_keys(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, reconciler_mode="metalbox")
        write = MagicMock()
        monkeypatch.setattr(handler, "write_dnsmasq_to_device", write)
        monkeypatch.setattr(
            handler.interface_handler,
            "get_virtual_interfaces_for_dnsmasq",
            MagicMock(return_value=["vlan100"]),
        )
        dyn = MagicMock(return_value=["metalbox,192.0.2.1,vlan100"])
        opts = MagicMock(return_value=["tag:vlan100,6,192.0.2.1"])
        monkeypatch.setattr(handler, "get_dynamic_hosts_for_metalbox", dyn)
        monkeypatch.setattr(handler, "get_dhcp_options_for_metalbox", opts)

        metalbox = make_device(
            1,
            "metalbox",
            role=make_tag("metalbox"),
            device_type=SimpleNamespace(slug="metal"),
        )
        node = make_device(
            2,
            "node1",
            role=make_tag("compute"),
            device_type=SimpleNamespace(slug="server"),
        )
        client = MagicMock()
        client.get_device_oob_interface.side_effect = _oob(
            {
                1: ("192.0.2.1", "aa:aa:aa:aa:aa:aa", None),
                2: ("192.0.2.10", "bb:bb:bb:bb:bb:bb", None),
            }
        )
        client.update_device_custom_field.return_value = True

        handler.process_devices(client, [metalbox], [metalbox, node])

        write.assert_called_once()
        written = write.call_args.args[1]
        assert set(written) == {
            "dnsmasq_dhcp_hosts__metalbox",
            "dnsmasq_dhcp_macs__metalbox",
            "dnsmasq_interfaces__metalbox",
            "dnsmasq_dynamic_hosts__metalbox",
            "dnsmasq_dhcp_options__metalbox",
        }
        assert written["dnsmasq_dhcp_hosts__metalbox"] == [
            "aa:aa:aa:aa:aa:aa,metalbox,192.0.2.1",
            "bb:bb:bb:bb:bb:bb,node1,192.0.2.10",
        ]
        assert written["dnsmasq_dhcp_macs__metalbox"] == [
            "set:metal,aa:aa:aa:aa:aa:aa",
            "set:server,bb:bb:bb:bb:bb:bb",
        ]
        assert written["dnsmasq_interfaces__metalbox"] == ["vlan100"]
        assert written["dnsmasq_dynamic_hosts__metalbox"] == [
            "metalbox,192.0.2.1,vlan100"
        ]
        assert written["dnsmasq_dhcp_options__metalbox"] == ["tag:vlan100,6,192.0.2.1"]
        dyn.assert_called_once()
        opts.assert_called_once()

        # No switch devices are present, so the switch-only overwrite
        # (guarded by ``if switch_dhcp_hosts or switch_dhcp_macs``) never runs.
        # The metalbox custom field therefore RETAINS its own collection-time
        # params -- this is intended: "discard metalbox own parameters" only
        # applies once there are switch params to write in their place. The
        # single metalbox custom-field write below (and the absence of a second,
        # switch-only one) locks that behavior in.
        metalbox_field_calls = [
            call
            for call in client.update_device_custom_field.call_args_list
            if call.args[0] is metalbox
        ]
        assert len(metalbox_field_calls) == 1
        assert metalbox_field_calls[-1].args[1] == "dnsmasq_parameters"
        assert metalbox_field_calls[-1].args[2] == {
            "dnsmasq_dhcp_hosts": ["aa:aa:aa:aa:aa:aa,metalbox,192.0.2.1"],
            "dnsmasq_dhcp_macs": ["set:metal,aa:aa:aa:aa:aa:aa"],
            "dnsmasq_interfaces": ["vlan100"],
        }

    def test_bridged_deduplicates_by_hostname_and_mac(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, reconciler_mode="metalbox")
        write = MagicMock()
        monkeypatch.setattr(handler, "write_dnsmasq_to_device", write)
        monkeypatch.setattr(
            handler.interface_handler,
            "get_virtual_interfaces_for_dnsmasq",
            MagicMock(return_value=["vlan100"]),
        )
        monkeypatch.setattr(
            handler, "get_dynamic_hosts_for_metalbox", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            handler, "get_dhcp_options_for_metalbox", MagicMock(return_value=[])
        )

        metalbox = make_device(
            1,
            "metalbox",
            role=make_tag("metalbox"),
            device_type=SimpleNamespace(slug="metal"),
        )
        # Two devices that resolve to the same hostname and MAC -> collapse.
        dup_a = make_device(
            2,
            "dup",
            role=make_tag("compute"),
            device_type=SimpleNamespace(slug="server"),
        )
        dup_b = make_device(
            3,
            "raw",
            role=make_tag("compute"),
            device_type=SimpleNamespace(slug="server"),
            custom_fields={"inventory_hostname": "dup"},
        )
        client = MagicMock()
        client.get_device_oob_interface.side_effect = _oob(
            {
                1: ("192.0.2.1", "aa:aa:aa:aa:aa:aa", None),
                2: ("192.0.2.10", "bb:bb:bb:bb:bb:bb", None),
                3: ("192.0.2.10", "bb:bb:bb:bb:bb:bb", None),
            }
        )
        client.update_device_custom_field.return_value = True

        handler.process_devices(client, [metalbox], [metalbox, dup_a, dup_b])

        written = write.call_args.args[1]
        # Metalbox + the single deduped "dup" host / MAC.
        assert written["dnsmasq_dhcp_hosts__metalbox"] == [
            "aa:aa:aa:aa:aa:aa,metalbox,192.0.2.1",
            "bb:bb:bb:bb:bb:bb,dup,192.0.2.10",
        ]
        assert written["dnsmasq_dhcp_macs__metalbox"] == [
            "set:metal,aa:aa:aa:aa:aa:aa",
            "set:server,bb:bb:bb:bb:bb:bb",
        ]

    def test_routed_uses_routed_helpers_and_set_tags(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, reconciler_mode="metalbox")
        write = MagicMock()
        monkeypatch.setattr(handler, "write_dnsmasq_to_device", write)
        # No VLAN interfaces on the metalbox -> routed mode.
        monkeypatch.setattr(
            handler.interface_handler,
            "get_virtual_interfaces_for_dnsmasq",
            MagicMock(return_value=[]),
        )
        monkeypatch.setattr(
            handler,
            "_get_metalbox_oob_virtual_interface",
            MagicMock(return_value=("192.0.2.254", "oob0")),
        )
        monkeypatch.setattr(
            handler,
            "_get_physical_uplink_interfaces",
            MagicMock(return_value=["uplink0"]),
        )
        bridged_dyn = MagicMock(return_value=["should-not-be-used"])
        bridged_opts = MagicMock(return_value=["should-not-be-used"])
        monkeypatch.setattr(handler, "get_dynamic_hosts_for_metalbox", bridged_dyn)
        monkeypatch.setattr(handler, "get_dhcp_options_for_metalbox", bridged_opts)

        metalbox = make_device(
            1,
            "metalbox",
            role=make_tag("metalbox"),
            device_type=SimpleNamespace(slug="metal"),
        )
        node = make_device(
            2,
            "node1",
            role=make_tag("compute"),
            device_type=SimpleNamespace(slug="server"),
        )
        client = MagicMock()
        client.get_oob_networks.return_value = [
            make_prefix("192.0.2.0/24", vlan=make_vlan(100))
        ]
        client.get_device_oob_interface.side_effect = _oob(
            {
                1: ("192.0.2.254", "aa:aa:aa:aa:aa:aa", None),
                2: ("192.0.2.10", "bb:bb:bb:bb:bb:bb", None),
            }
        )
        client.update_device_custom_field.return_value = True

        handler.process_devices(client, [metalbox], [metalbox, node])

        written = write.call_args.args[1]
        # set_tag derived from the prefix mapping (vlan100) is appended to hosts.
        assert written["dnsmasq_dhcp_hosts__metalbox"] == [
            "aa:aa:aa:aa:aa:aa,metalbox,192.0.2.254,set:vlan100",
            "bb:bb:bb:bb:bb:bb,node1,192.0.2.10,set:vlan100",
        ]
        # Routed helpers drive interfaces / dynamic hosts / options.
        assert written["dnsmasq_interfaces__metalbox"] == ["oob0", "uplink0"]
        assert written["dnsmasq_dynamic_hosts__metalbox"] == [
            "metalbox,192.0.2.254,oob0",
            "metalbox.osism.xyz,192.0.2.254,oob0",
        ]
        assert written["dnsmasq_dhcp_options__metalbox"] == [
            "tag:vlan100,3,192.0.2.1",
            "tag:vlan100,6,192.0.2.254",
            "tag:vlan100,42,192.0.2.254",
        ]
        bridged_dyn.assert_not_called()
        bridged_opts.assert_not_called()

    def test_routed_unresolved_metalbox_interface_skips_write(
        self, tmp_path, monkeypatch, mock_logger
    ):
        handler = _handler(tmp_path, reconciler_mode="metalbox")
        write = MagicMock()
        monkeypatch.setattr(handler, "write_dnsmasq_to_device", write)
        # No VLAN interfaces on the metalbox -> routed mode.
        monkeypatch.setattr(
            handler.interface_handler,
            "get_virtual_interfaces_for_dnsmasq",
            MagicMock(return_value=[]),
        )

        metalbox = make_device(
            1,
            "metalbox",
            role=make_tag("metalbox"),
            device_type=SimpleNamespace(slug="metal"),
        )
        node = make_device(
            2,
            "node1",
            role=make_tag("compute"),
            device_type=SimpleNamespace(slug="server"),
        )
        client = MagicMock()
        # Real _get_metalbox_oob_virtual_interface runs against an interface-less
        # fake API and therefore returns its genuine (None, None) -- no
        # loopback0, no virtual interface to resolve an IP/name from.
        client.api = make_fake_api(interfaces=[])
        client.get_oob_networks.return_value = [
            make_prefix("192.0.2.0/24", vlan=make_vlan(100))
        ]
        client.get_device_oob_interface.side_effect = _oob(
            {
                1: ("192.0.2.254", "aa:aa:aa:aa:aa:aa", None),
                2: ("192.0.2.10", "bb:bb:bb:bb:bb:bb", None),
            }
        )
        client.update_device_custom_field.return_value = True

        handler.process_devices(client, [metalbox], [metalbox, node])

        # The routed write is aborted rather than emitting a "metalbox,None,None"
        # config, and the skip is surfaced as a warning.
        write.assert_not_called()
        assert any(
            "skipping dnsmasq write" in call.args[0]
            for call in mock_logger.warning.call_args_list
        )

    def test_switch_tracking_excludes_metalbox_own_params(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, reconciler_mode="metalbox")
        write = MagicMock()
        monkeypatch.setattr(handler, "write_dnsmasq_to_device", write)
        monkeypatch.setattr(
            handler.interface_handler,
            "get_virtual_interfaces_for_dnsmasq",
            MagicMock(return_value=["vlan100"]),
        )
        monkeypatch.setattr(
            handler, "get_dynamic_hosts_for_metalbox", MagicMock(return_value=["dh"])
        )
        monkeypatch.setattr(
            handler, "get_dhcp_options_for_metalbox", MagicMock(return_value=["do"])
        )

        metalbox = make_device(
            1,
            "metalbox",
            role=make_tag("metalbox"),
            device_type=SimpleNamespace(slug="metal"),
        )
        leaf = make_device(
            2,
            "leaf1",
            role=make_tag("leaf"),
            device_type=SimpleNamespace(slug="switch"),
        )
        client = MagicMock()
        client.get_device_oob_interface.side_effect = _oob(
            {
                1: ("192.0.2.1", "aa:aa:aa:aa:aa:aa", None),
                2: ("192.0.2.2", "bb:bb:bb:bb:bb:bb", None),
            }
        )
        client.update_device_custom_field.return_value = True

        handler.process_devices(client, [metalbox], [metalbox, leaf])

        # Final custom-field write caches only the switch params on the metalbox.
        last_call = client.update_device_custom_field.call_args_list[-1]
        assert last_call.args[0] is metalbox
        cached = last_call.args[2]
        assert cached["dnsmasq_dhcp_hosts"] == ["bb:bb:bb:bb:bb:bb,leaf1,192.0.2.2"]
        assert cached["dnsmasq_dhcp_macs"] == ["set:switch,bb:bb:bb:bb:bb:bb"]
        assert (
            "aa:aa:aa:aa:aa:aa,metalbox,192.0.2.1" not in cached["dnsmasq_dhcp_hosts"]
        )
        # The written file still carries both metalbox and switch host entries.
        written = write.call_args.args[1]
        assert (
            "aa:aa:aa:aa:aa:aa,metalbox,192.0.2.1"
            in written["dnsmasq_dhcp_hosts__metalbox"]
        )
        assert (
            "bb:bb:bb:bb:bb:bb,leaf1,192.0.2.2"
            in written["dnsmasq_dhcp_hosts__metalbox"]
        )

    def test_mac_without_ip_contributes_mac_entry_only(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, reconciler_mode="metalbox")
        write = MagicMock()
        monkeypatch.setattr(handler, "write_dnsmasq_to_device", write)
        monkeypatch.setattr(
            handler.interface_handler,
            "get_virtual_interfaces_for_dnsmasq",
            MagicMock(return_value=["vlan100"]),
        )
        monkeypatch.setattr(
            handler, "get_dynamic_hosts_for_metalbox", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            handler, "get_dhcp_options_for_metalbox", MagicMock(return_value=[])
        )

        metalbox = make_device(
            1,
            "metalbox",
            role=make_tag("metalbox"),
            device_type=SimpleNamespace(slug="metal"),
        )
        node = make_device(
            2,
            "node1",
            role=make_tag("compute"),
            device_type=SimpleNamespace(slug="server"),
        )
        client = MagicMock()
        client.get_device_oob_interface.side_effect = _oob(
            {
                1: ("192.0.2.1", "aa:aa:aa:aa:aa:aa", None),
                2: (None, "bb:bb:bb:bb:bb:bb", None),  # MAC but no IP
            }
        )
        client.update_device_custom_field.return_value = True

        handler.process_devices(client, [metalbox], [metalbox, node])

        written = write.call_args.args[1]
        assert written["dnsmasq_dhcp_hosts__metalbox"] == [
            "aa:aa:aa:aa:aa:aa,metalbox,192.0.2.1"
        ]
        assert "set:server,bb:bb:bb:bb:bb:bb" in written["dnsmasq_dhcp_macs__metalbox"]

    def test_non_mac_metalbox_caches_virtual_interfaces(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, reconciler_mode="metalbox")
        write = MagicMock()
        monkeypatch.setattr(handler, "write_dnsmasq_to_device", write)
        monkeypatch.setattr(
            handler.interface_handler,
            "get_virtual_interfaces_for_dnsmasq",
            MagicMock(return_value=["vlan100"]),
        )
        monkeypatch.setattr(
            handler, "get_dynamic_hosts_for_metalbox", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            handler, "get_dhcp_options_for_metalbox", MagicMock(return_value=[])
        )

        metalbox = make_device(
            1,
            "metalbox",
            role=make_tag("metalbox"),
            device_type=SimpleNamespace(slug="metal"),
        )
        client = MagicMock()
        client.get_device_oob_interface.side_effect = _oob({1: (None, None, None)})
        client.update_device_custom_field.return_value = True

        handler.process_devices(client, [metalbox], [metalbox])

        # Line-730 path: the metalbox's virtual interfaces are cached even
        # though it has no OOB MAC.
        client.update_device_custom_field.assert_called_once_with(
            metalbox,
            "dnsmasq_parameters",
            {
                "dnsmasq_dhcp_hosts": [],
                "dnsmasq_dhcp_macs": [],
                "dnsmasq_interfaces": ["vlan100"],
            },
        )
        written = write.call_args.args[1]
        assert written["dnsmasq_interfaces__metalbox"] == ["vlan100"]
        assert written["dnsmasq_dhcp_hosts__metalbox"] == []

    def test_falsy_custom_field_update_warns(self, tmp_path, monkeypatch, mock_logger):
        handler = _handler(tmp_path, reconciler_mode="metalbox")
        monkeypatch.setattr(handler, "write_dnsmasq_to_device", MagicMock())
        monkeypatch.setattr(
            handler.interface_handler,
            "get_virtual_interfaces_for_dnsmasq",
            MagicMock(return_value=["vlan100"]),
        )
        monkeypatch.setattr(
            handler, "get_dynamic_hosts_for_metalbox", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            handler, "get_dhcp_options_for_metalbox", MagicMock(return_value=[])
        )

        metalbox = make_device(
            1,
            "metalbox",
            role=make_tag("metalbox"),
            device_type=SimpleNamespace(slug="metal"),
        )
        client = MagicMock()
        client.get_device_oob_interface.side_effect = _oob(
            {1: ("192.0.2.1", "aa:aa:aa:aa:aa:aa", None)}
        )
        client.update_device_custom_field.return_value = False

        handler.process_devices(client, [metalbox], [metalbox])

        assert any(
            "Failed to cache" in call.args[0]
            for call in mock_logger.warning.call_args_list
        )
