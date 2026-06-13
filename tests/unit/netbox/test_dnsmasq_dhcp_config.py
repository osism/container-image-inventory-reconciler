# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/dnsmasq/dhcp_config.py.

The ``DHCPConfigGenerator`` turns the OOB view of a device into dnsmasq DHCP
host / MAC entries and writes OOB DHCP ranges into the generated inventory
tree. The host/MAC formatting tests drive plain ``SimpleNamespace`` device
stubs; ``write_dhcp_ranges`` writes under ``config.inventory_path`` (pytest's
``tmp_path``) through a ``MagicMock``-backed fake ``NetBoxClient`` whose
``get_oob_networks()`` return value is stubbed per scenario. The module-level
``loguru`` logger is patched with a ``MagicMock`` only where a log assertion
documents the branch taken.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml

from dnsmasq.dhcp_config import DHCPConfigGenerator

from .conftest import make_device, make_dnsmasq_config, make_prefix


@pytest.fixture
def mock_logger(monkeypatch):
    """Replace the module-level loguru logger with a MagicMock."""
    logger = MagicMock()
    monkeypatch.setattr("dnsmasq.dhcp_config.logger", logger)
    return logger


def _gen(tmp_path, **overrides):
    """Build a DHCPConfigGenerator with a dnsmasq config stub."""
    return DHCPConfigGenerator(make_dnsmasq_config(tmp_path, **overrides))


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestInit:
    def test_stores_config(self, tmp_path):
        config = make_dnsmasq_config(tmp_path)
        assert DHCPConfigGenerator(config).config is config


# ---------------------------------------------------------------------------
# generate_dhcp_host_entry
# ---------------------------------------------------------------------------


class TestGenerateDhcpHostEntry:
    def test_plain_entry_lowercases_mac_and_uses_hostname(self, tmp_path):
        gen = _gen(tmp_path)
        device = make_device(1, "node1")
        entry = gen.generate_dhcp_host_entry(device, "192.0.2.10", "AA:BB:CC:DD:EE:FF")
        assert entry == "aa:bb:cc:dd:ee:ff,node1,192.0.2.10"

    def test_explicit_set_tag_wins_even_with_vlan_id(self, tmp_path):
        # set_tag branch precedes the vlan branch, even in metalbox mode.
        gen = _gen(tmp_path, reconciler_mode="metalbox")
        device = make_device(1, "node1")
        entry = gen.generate_dhcp_host_entry(
            device, "192.0.2.10", "aa:bb:cc:dd:ee:ff", vlan_id=100, set_tag="oob"
        )
        assert entry == "aa:bb:cc:dd:ee:ff,node1,192.0.2.10,set:oob"

    def test_vlan_id_in_metalbox_mode_adds_vlan_tag(self, tmp_path):
        gen = _gen(tmp_path, reconciler_mode="metalbox")
        device = make_device(1, "node1")
        entry = gen.generate_dhcp_host_entry(
            device, "192.0.2.10", "aa:bb:cc:dd:ee:ff", vlan_id=100
        )
        assert entry == "aa:bb:cc:dd:ee:ff,node1,192.0.2.10,set:vlan100"

    def test_vlan_id_ignored_outside_metalbox_mode(self, tmp_path):
        gen = _gen(tmp_path, reconciler_mode="manager")
        device = make_device(1, "node1")
        entry = gen.generate_dhcp_host_entry(
            device, "192.0.2.10", "aa:bb:cc:dd:ee:ff", vlan_id=100
        )
        assert entry == "aa:bb:cc:dd:ee:ff,node1,192.0.2.10"

    def test_hostname_honours_inventory_hostname_custom_field(self, tmp_path):
        gen = _gen(tmp_path)
        device = make_device(
            1, "raw-name", custom_fields={"inventory_hostname": "pretty"}
        )
        entry = gen.generate_dhcp_host_entry(device, "192.0.2.10", "aa:bb:cc:dd:ee:ff")
        assert entry == "aa:bb:cc:dd:ee:ff,pretty,192.0.2.10"

    def test_hostname_falls_back_to_device_name(self, tmp_path):
        gen = _gen(tmp_path)
        device = make_device(1, "raw-name", custom_fields={})
        entry = gen.generate_dhcp_host_entry(device, "192.0.2.10", "aa:bb:cc:dd:ee:ff")
        assert entry == "aa:bb:cc:dd:ee:ff,raw-name,192.0.2.10"


# ---------------------------------------------------------------------------
# generate_dhcp_mac_entry
# ---------------------------------------------------------------------------


class TestGenerateDhcpMacEntry:
    def test_priority1_custom_dhcp_tag(self, tmp_path):
        gen = _gen(tmp_path)
        device = make_device(1, "n", custom_fields={"dnsmasq_dhcp_tag": "customtag"})
        assert (
            gen.generate_dhcp_mac_entry(device, "AA:BB:CC:DD:EE:FF")
            == "set:customtag,aa:bb:cc:dd:ee:ff"
        )

    def test_priority2_managed_by_ironic_tag(self, tmp_path):
        gen = _gen(tmp_path)
        device = make_device(1, "n", tags=("managed-by-ironic",))
        assert (
            gen.generate_dhcp_mac_entry(device, "AA:BB:CC:DD:EE:FF")
            == "set:ironic,aa:bb:cc:dd:ee:ff"
        )

    def test_priority3_device_type_slug(self, tmp_path):
        gen = _gen(tmp_path)
        device = make_device(1, "n", device_type=SimpleNamespace(slug="server"))
        assert (
            gen.generate_dhcp_mac_entry(device, "AA:BB:CC:DD:EE:FF")
            == "set:server,aa:bb:cc:dd:ee:ff"
        )

    def test_custom_tag_wins_over_ironic_and_device_type(self, tmp_path):
        gen = _gen(tmp_path)
        device = make_device(
            1,
            "n",
            tags=("managed-by-ironic",),
            custom_fields={"dnsmasq_dhcp_tag": "customtag"},
            device_type=SimpleNamespace(slug="server"),
        )
        assert (
            gen.generate_dhcp_mac_entry(device, "aa:bb:cc:dd:ee:ff")
            == "set:customtag,aa:bb:cc:dd:ee:ff"
        )

    def test_ironic_wins_over_device_type(self, tmp_path):
        gen = _gen(tmp_path)
        device = make_device(
            1,
            "n",
            tags=("managed-by-ironic",),
            device_type=SimpleNamespace(slug="server"),
        )
        assert (
            gen.generate_dhcp_mac_entry(device, "aa:bb:cc:dd:ee:ff")
            == "set:ironic,aa:bb:cc:dd:ee:ff"
        )

    def test_no_tag_source_returns_none(self, tmp_path):
        gen = _gen(tmp_path)
        device = make_device(1, "n")
        assert gen.generate_dhcp_mac_entry(device, "aa:bb:cc:dd:ee:ff") is None

    def test_device_type_without_slug_returns_none(self, tmp_path):
        gen = _gen(tmp_path)
        device = make_device(1, "n", device_type=SimpleNamespace(slug=None))
        assert gen.generate_dhcp_mac_entry(device, "aa:bb:cc:dd:ee:ff") is None


# ---------------------------------------------------------------------------
# write_dhcp_ranges
# ---------------------------------------------------------------------------


def _range_file(tmp_path):
    return tmp_path / "group_vars" / "manager" / "999-netbox-dnsmasq-dhcp-range.yml"


class TestWriteDhcpRanges:
    def test_no_oob_networks_writes_nothing(self, tmp_path, mock_logger):
        gen = _gen(tmp_path)
        client = MagicMock()
        client.get_oob_networks.return_value = []

        gen.write_dhcp_ranges(client)

        assert not _range_file(tmp_path).exists()
        mock_logger.debug.assert_called_once()

    def test_ipv4_without_prefix_tags(self, tmp_path):
        gen = _gen(tmp_path)
        client = MagicMock()
        client.get_oob_networks.return_value = [make_prefix("192.0.2.0/24")]

        gen.write_dhcp_ranges(client)

        output_file = _range_file(tmp_path)
        assert output_file.exists()
        data = yaml.safe_load(output_file.read_text())
        assert isinstance(data["dnsmasq_dhcp_ranges"], list)
        assert data["dnsmasq_dhcp_ranges"] == ["192.0.2.0,static,255.255.255.0,28d"]

    def test_ipv6_network_is_skipped(self, tmp_path):
        gen = _gen(tmp_path)
        client = MagicMock()
        client.get_oob_networks.return_value = [make_prefix("2001:db8::/64")]

        gen.write_dhcp_ranges(client)

        assert not _range_file(tmp_path).exists()

    def test_prefix_tags_only_emits_mapped_prefixes(self, tmp_path):
        gen = _gen(tmp_path)
        client = MagicMock()
        client.get_oob_networks.return_value = [
            make_prefix("192.0.2.0/24"),
            make_prefix("198.51.100.0/24"),
        ]

        gen.write_dhcp_ranges(client, prefix_tags={"192.0.2.0/24": "oob"})

        data = yaml.safe_load(_range_file(tmp_path).read_text())
        assert data["dnsmasq_dhcp_ranges"] == [
            "set:oob,192.0.2.0,static,255.255.255.0,28d"
        ]

    def test_malformed_prefix_warns_and_continues(self, tmp_path, mock_logger):
        gen = _gen(tmp_path)
        client = MagicMock()
        client.get_oob_networks.return_value = [
            make_prefix("nope"),
            make_prefix("192.0.2.0/24"),
        ]

        gen.write_dhcp_ranges(client)

        mock_logger.warning.assert_called_once()
        data = yaml.safe_load(_range_file(tmp_path).read_text())
        assert data["dnsmasq_dhcp_ranges"] == ["192.0.2.0,static,255.255.255.0,28d"]

    def test_all_networks_invalid_writes_nothing(self, tmp_path):
        gen = _gen(tmp_path)
        client = MagicMock()
        client.get_oob_networks.return_value = [make_prefix("nope")]

        gen.write_dhcp_ranges(client)

        assert not _range_file(tmp_path).exists()

    def test_lease_time_is_read_from_config(self, tmp_path):
        gen = _gen(tmp_path, dnsmasq_lease_time="12h")
        client = MagicMock()
        client.get_oob_networks.return_value = [make_prefix("192.0.2.0/24")]

        gen.write_dhcp_ranges(client)

        data = yaml.safe_load(_range_file(tmp_path).read_text())
        assert data["dnsmasq_dhcp_ranges"] == ["192.0.2.0,static,255.255.255.0,12h"]
