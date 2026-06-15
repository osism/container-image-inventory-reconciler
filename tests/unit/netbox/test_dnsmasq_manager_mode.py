# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/dnsmasq/manager_mode.py.

``ManagerModeHandler`` generates per-device dnsmasq host / MAC entries from the
OOB interface (``process_devices``) or replays cached parameters from the
device custom field (``process_devices_readonly``). The collaborator is a
``MagicMock``-backed fake ``NetBoxClient`` whose ``get_device_oob_interface``
and ``update_device_custom_field`` are stubbed per scenario;
``write_dnsmasq_to_device`` (covered by the base tests) is replaced with a
``MagicMock`` so the tests assert on the keys / call counts it receives. The
module-level ``loguru`` logger is patched only where a log assertion documents
the branch taken.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from dnsmasq.manager_mode import ManagerModeHandler

from .conftest import make_device, make_dnsmasq_config


@pytest.fixture
def mock_logger(monkeypatch):
    """Replace the module-level loguru logger with a MagicMock."""
    logger = MagicMock()
    monkeypatch.setattr("dnsmasq.manager_mode.logger", logger)
    return logger


def _handler(tmp_path, monkeypatch):
    """Build a ManagerModeHandler with write_dnsmasq_to_device mocked out."""
    handler = ManagerModeHandler(make_dnsmasq_config(tmp_path))
    monkeypatch.setattr(handler, "write_dnsmasq_to_device", MagicMock())
    return handler


def _client(oob, update_return=True):
    client = MagicMock()
    client.get_device_oob_interface.return_value = oob
    client.update_device_custom_field.return_value = update_return
    return client


class TestProcessDevices:
    def test_mac_and_ip_generates_host_and_mac_entries(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, monkeypatch)
        device = make_device(1, "node1", device_type=SimpleNamespace(slug="server"))
        client = _client(("192.0.2.10", "aa:bb:cc:dd:ee:ff", None))

        handler.process_devices(client, [device])

        client.update_device_custom_field.assert_called_once_with(
            device,
            "dnsmasq_parameters",
            {
                "dnsmasq_dhcp_hosts": ["aa:bb:cc:dd:ee:ff,node1,192.0.2.10"],
                "dnsmasq_dhcp_macs": ["set:server,aa:bb:cc:dd:ee:ff"],
            },
        )
        handler.write_dnsmasq_to_device.assert_called_once()
        written = handler.write_dnsmasq_to_device.call_args.args[1]
        assert written == {
            "dnsmasq_dhcp_hosts__node1": ["aa:bb:cc:dd:ee:ff,node1,192.0.2.10"],
            "dnsmasq_dhcp_macs__node1": ["set:server,aa:bb:cc:dd:ee:ff"],
        }

    def test_mac_without_ip_skips_host_entry(self, tmp_path, monkeypatch, mock_logger):
        handler = _handler(tmp_path, monkeypatch)
        device = make_device(1, "node1", device_type=SimpleNamespace(slug="server"))
        client = _client((None, "aa:bb:cc:dd:ee:ff", None))

        handler.process_devices(client, [device])

        written = handler.write_dnsmasq_to_device.call_args.args[1]
        assert "dnsmasq_dhcp_hosts__node1" not in written
        assert written["dnsmasq_dhcp_macs__node1"] == ["set:server,aa:bb:cc:dd:ee:ff"]
        # Cached host list stays empty when there is no IP.
        params = client.update_device_custom_field.call_args.args[2]
        assert params["dnsmasq_dhcp_hosts"] == []
        assert any(
            "no IP address" in call.args[0] for call in mock_logger.info.call_args_list
        )

    def test_no_mac_skips_device_entirely(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, monkeypatch)
        device = make_device(1, "node1", device_type=SimpleNamespace(slug="server"))
        client = _client((None, None, None))

        handler.process_devices(client, [device])

        client.update_device_custom_field.assert_not_called()
        handler.write_dnsmasq_to_device.assert_not_called()

    def test_no_tag_source_and_no_ip_caches_but_does_not_write(
        self, tmp_path, monkeypatch
    ):
        handler = _handler(tmp_path, monkeypatch)
        device = make_device(1, "node1")  # no device_type / tags / custom tag
        client = _client((None, "aa:bb:cc:dd:ee:ff", None))

        handler.process_devices(client, [device])

        # Custom field still written (empty lists), but no file is written
        # because dnsmasq_data ends up empty (the `if dnsmasq_data` guard).
        client.update_device_custom_field.assert_called_once_with(
            device,
            "dnsmasq_parameters",
            {"dnsmasq_dhcp_hosts": [], "dnsmasq_dhcp_macs": []},
        )
        handler.write_dnsmasq_to_device.assert_not_called()

    def test_falsy_custom_field_update_warns(self, tmp_path, monkeypatch, mock_logger):
        handler = _handler(tmp_path, monkeypatch)
        device = make_device(1, "node1", device_type=SimpleNamespace(slug="server"))
        client = _client(("192.0.2.10", "aa:bb:cc:dd:ee:ff", None), update_return=False)

        handler.process_devices(client, [device])

        mock_logger.warning.assert_called_once()


class TestProcessDevicesReadonly:
    def test_no_cached_params_skips(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, monkeypatch)

        handler.process_devices_readonly([make_device(1, "node1", custom_fields={})])

        handler.write_dnsmasq_to_device.assert_not_called()

    def test_none_custom_fields_skips(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, monkeypatch)
        device = SimpleNamespace(name="node1", custom_fields=None)

        handler.process_devices_readonly([device])

        handler.write_dnsmasq_to_device.assert_not_called()

    def test_cached_hosts_written(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, monkeypatch)
        device = make_device(
            1,
            "node1",
            custom_fields={"dnsmasq_parameters": {"dnsmasq_dhcp_hosts": ["h"]}},
        )

        handler.process_devices_readonly([device])

        written = handler.write_dnsmasq_to_device.call_args.args[1]
        assert written == {"dnsmasq_dhcp_hosts__node1": ["h"]}

    def test_cached_macs_written(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, monkeypatch)
        device = make_device(
            1,
            "node1",
            custom_fields={"dnsmasq_parameters": {"dnsmasq_dhcp_macs": ["m"]}},
        )

        handler.process_devices_readonly([device])

        written = handler.write_dnsmasq_to_device.call_args.args[1]
        assert written == {"dnsmasq_dhcp_macs__node1": ["m"]}

    def test_cached_hosts_and_macs_written(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, monkeypatch)
        device = make_device(
            1,
            "node1",
            custom_fields={
                "dnsmasq_parameters": {
                    "dnsmasq_dhcp_hosts": ["h"],
                    "dnsmasq_dhcp_macs": ["m"],
                }
            },
        )

        handler.process_devices_readonly([device])

        written = handler.write_dnsmasq_to_device.call_args.args[1]
        assert written == {
            "dnsmasq_dhcp_hosts__node1": ["h"],
            "dnsmasq_dhcp_macs__node1": ["m"],
        }

    def test_cached_empty_lists_no_write(self, tmp_path, monkeypatch):
        handler = _handler(tmp_path, monkeypatch)
        device = make_device(
            1,
            "node1",
            custom_fields={
                "dnsmasq_parameters": {
                    "dnsmasq_dhcp_hosts": [],
                    "dnsmasq_dhcp_macs": [],
                }
            },
        )

        handler.process_devices_readonly([device])

        handler.write_dnsmasq_to_device.assert_not_called()
