# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/dnsmasq/manager.py.

``DnsmasqManager`` is a thin dispatcher: ``write_dnsmasq_config`` routes to the
manager / readonly / metalbox handler depending on ``reconciler_mode`` (and
whether ``all_devices`` is supplied), and ``write_dnsmasq_dhcp_ranges``
delegates verbatim to the DHCP generator. The tests patch the instance
collaborators with ``MagicMock``s and assert exactly one path runs per mode --
no filesystem and no NetBox access are involved.
"""

from unittest.mock import MagicMock

from dnsmasq.dhcp_config import DHCPConfigGenerator
from dnsmasq.manager import DnsmasqManager
from dnsmasq.manager_mode import ManagerModeHandler
from dnsmasq.metalbox_mode import MetalboxModeHandler

from .conftest import make_device, make_dnsmasq_config


def _manager(tmp_path, monkeypatch, *, reconciler_mode="manager"):
    mgr = DnsmasqManager(make_dnsmasq_config(tmp_path, reconciler_mode=reconciler_mode))
    monkeypatch.setattr(mgr, "manager_handler", MagicMock())
    monkeypatch.setattr(mgr, "metalbox_handler", MagicMock())
    monkeypatch.setattr(mgr, "dhcp_generator", MagicMock())
    return mgr


DEVICES = [make_device(1, "node1")]
ALL_DEVICES = [make_device(2, "node2")]


class TestInit:
    def test_constructs_collaborators(self, tmp_path):
        mgr = DnsmasqManager(make_dnsmasq_config(tmp_path))
        assert isinstance(mgr.dhcp_generator, DHCPConfigGenerator)
        assert isinstance(mgr.manager_handler, ManagerModeHandler)
        assert isinstance(mgr.metalbox_handler, MetalboxModeHandler)


class TestWriteDnsmasqConfig:
    def test_manager_readonly_calls_readonly_only(self, tmp_path, monkeypatch):
        mgr = _manager(tmp_path, monkeypatch, reconciler_mode="manager-readonly")
        client = MagicMock()

        mgr.write_dnsmasq_config(client, DEVICES, all_devices=ALL_DEVICES)

        mgr.manager_handler.process_devices_readonly.assert_called_once_with(DEVICES)
        mgr.manager_handler.process_devices.assert_not_called()
        mgr.metalbox_handler.process_devices.assert_not_called()
        # Read-only path never touches the NetBox client.
        client.get_device_oob_interface.assert_not_called()
        client.update_device_custom_field.assert_not_called()

    def test_metalbox_with_all_devices_calls_metalbox(self, tmp_path, monkeypatch):
        mgr = _manager(tmp_path, monkeypatch, reconciler_mode="metalbox")
        client = MagicMock()

        mgr.write_dnsmasq_config(client, DEVICES, all_devices=ALL_DEVICES)

        mgr.metalbox_handler.process_devices.assert_called_once_with(
            client, DEVICES, ALL_DEVICES
        )
        mgr.manager_handler.process_devices.assert_not_called()
        mgr.manager_handler.process_devices_readonly.assert_not_called()

    def test_metalbox_without_all_devices_falls_through_to_manager(
        self, tmp_path, monkeypatch
    ):
        mgr = _manager(tmp_path, monkeypatch, reconciler_mode="metalbox")
        client = MagicMock()

        mgr.write_dnsmasq_config(client, DEVICES, all_devices=None)

        mgr.manager_handler.process_devices.assert_called_once_with(client, DEVICES)
        mgr.metalbox_handler.process_devices.assert_not_called()

    def test_metalbox_with_empty_all_devices_falls_through_to_manager(
        self, tmp_path, monkeypatch
    ):
        mgr = _manager(tmp_path, monkeypatch, reconciler_mode="metalbox")
        client = MagicMock()

        mgr.write_dnsmasq_config(client, DEVICES, all_devices=[])

        mgr.manager_handler.process_devices.assert_called_once_with(client, DEVICES)
        mgr.metalbox_handler.process_devices.assert_not_called()

    def test_manager_mode_calls_process_devices(self, tmp_path, monkeypatch):
        mgr = _manager(tmp_path, monkeypatch, reconciler_mode="manager")
        client = MagicMock()

        mgr.write_dnsmasq_config(client, DEVICES)

        mgr.manager_handler.process_devices.assert_called_once_with(client, DEVICES)
        mgr.metalbox_handler.process_devices.assert_not_called()
        mgr.manager_handler.process_devices_readonly.assert_not_called()


class TestWriteDnsmasqDhcpRanges:
    def test_delegates_without_prefix_tags(self, tmp_path, monkeypatch):
        mgr = _manager(tmp_path, monkeypatch)
        client = MagicMock()

        mgr.write_dnsmasq_dhcp_ranges(client)

        mgr.dhcp_generator.write_dhcp_ranges.assert_called_once_with(
            client, prefix_tags=None
        )

    def test_delegates_with_prefix_tags(self, tmp_path, monkeypatch):
        mgr = _manager(tmp_path, monkeypatch)
        client = MagicMock()
        prefix_tags = {"192.0.2.0/24": "oob"}

        mgr.write_dnsmasq_dhcp_ranges(client, prefix_tags=prefix_tags)

        mgr.dhcp_generator.write_dhcp_ranges.assert_called_once_with(
            client, prefix_tags=prefix_tags
        )
