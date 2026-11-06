# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/inventory/file_writer.py.

Covers how ``FileWriter.write_device_data`` treats keys that a single-file
``host_vars/<host>.yml`` already defines outside a NetBox section: the manual
definition wins, a NetBox value equal to it is dropped quietly, and a
differing one is dropped with a warning naming both values. If the manual
part does not parse as YAML, matching keys are dropped with an info log.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml

from inventory.file_writer import FileWriter

from .conftest import make_device


@pytest.fixture
def mock_logger(monkeypatch):
    """Replace the module-level loguru logger with a MagicMock."""
    logger = MagicMock()
    monkeypatch.setattr("inventory.file_writer.logger", logger)
    return logger


def _writer(tmp_path):
    (tmp_path / "host_vars").mkdir()
    return FileWriter(SimpleNamespace(inventory_path=tmp_path))


def _host_file(tmp_path, content):
    path = tmp_path / "host_vars" / "node1.yml"
    path.write_text(content, encoding="utf-8")
    return path


DEVICE = make_device(1, "node1")


class TestPrimaryIpSingleFile:
    def test_same_ansible_host_is_skipped_quietly(self, tmp_path, mock_logger):
        writer = _writer(tmp_path)
        original = "ansible_host: 10.0.0.1\n"
        path = _host_file(tmp_path, original)

        writer.write_device_data(DEVICE, "primary_ip", "10.0.0.1")

        assert path.read_text(encoding="utf-8") == original
        mock_logger.warning.assert_not_called()
        mock_logger.info.assert_not_called()

    def test_different_ansible_host_is_skipped_with_warning(
        self, tmp_path, mock_logger
    ):
        writer = _writer(tmp_path)
        original = "ansible_host: 10.0.0.1\n"
        path = _host_file(tmp_path, original)

        writer.write_device_data(DEVICE, "primary_ip", "10.0.0.2")

        assert path.read_text(encoding="utf-8") == original
        mock_logger.warning.assert_called_once()
        message = mock_logger.warning.call_args.args[0]
        assert "ansible_host" in message
        assert "10.0.0.1" in message
        assert "10.0.0.2" in message

    def test_without_manual_ansible_host_is_appended(self, tmp_path, mock_logger):
        writer = _writer(tmp_path)
        path = _host_file(tmp_path, "foo: bar\n")

        writer.write_device_data(DEVICE, "primary_ip", "10.0.0.2")

        assert yaml.safe_load(path.read_text(encoding="utf-8")) == {
            "foo": "bar",
            "ansible_host": "10.0.0.2",
        }

    def test_earlier_netbox_section_does_not_count_as_manual(
        self, tmp_path, mock_logger
    ):
        writer = _writer(tmp_path)
        path = _host_file(
            tmp_path, "foo: bar\n\n# NetBox primary_ip\nansible_host: 10.0.0.1\n"
        )

        writer.write_device_data(DEVICE, "primary_ip", "10.0.0.2")

        content = path.read_text(encoding="utf-8")
        assert content.count("ansible_host") == 1
        assert yaml.safe_load(content)["ansible_host"] == "10.0.0.2"
        mock_logger.warning.assert_not_called()


class TestDictDataSingleFile:
    def test_same_value_is_skipped_quietly(self, tmp_path, mock_logger):
        writer = _writer(tmp_path)
        path = _host_file(tmp_path, "mtu: 9000\n")

        writer.write_device_data(
            DEVICE, "config_context", {"mtu": 9000, "other": "x"}
        )

        assert yaml.safe_load(path.read_text(encoding="utf-8")) == {
            "mtu": 9000,
            "other": "x",
        }
        mock_logger.warning.assert_not_called()
        mock_logger.info.assert_not_called()

    def test_different_value_is_skipped_with_warning(self, tmp_path, mock_logger):
        writer = _writer(tmp_path)
        path = _host_file(tmp_path, "mtu: 9000\n")

        writer.write_device_data(DEVICE, "config_context", {"mtu": 1500})

        assert path.read_text(encoding="utf-8") == "mtu: 9000\n"
        mock_logger.warning.assert_called_once()
        message = mock_logger.warning.call_args.args[0]
        assert "mtu" in message
        assert "9000" in message
        assert "1500" in message

    def test_secret_values_are_not_logged(self, tmp_path, mock_logger):
        writer = _writer(tmp_path)
        _host_file(tmp_path, "db_password: manual-secret\n")

        writer.write_device_data(
            DEVICE, "secrets", {"db_password": "netbox-secret"}
        )

        mock_logger.warning.assert_called_once()
        message = mock_logger.warning.call_args.args[0]
        assert "db_password" in message
        assert "manual-secret" not in message
        assert "netbox-secret" not in message

    def test_unparsable_manual_value_is_skipped_without_warning(
        self, tmp_path, mock_logger
    ):
        writer = _writer(tmp_path)
        original = "mtu: 9000\nbroken: [unclosed\n"
        path = _host_file(tmp_path, original)

        writer.write_device_data(DEVICE, "config_context", {"mtu": 1500})

        assert path.read_text(encoding="utf-8") == original
        mock_logger.warning.assert_not_called()
        mock_logger.info.assert_called_once()
