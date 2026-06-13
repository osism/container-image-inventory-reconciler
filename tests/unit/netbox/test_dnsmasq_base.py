# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/dnsmasq/base.py.

``DnsmasqBase.write_dnsmasq_to_device`` resolves a device's host_vars location
by globbing ``host_vars/{hostname}*`` under ``config.inventory_path`` (pytest's
``tmp_path``) and writes / appends a ``999-netbox-dnsmasq.yml`` file. The tests
pre-create the four glob shapes (existing dir, existing single file, no match,
multiple matches) in the real temp tree and assert on the files produced. The
module-level ``loguru`` logger is patched only where a log assertion documents
the branch taken.
"""

from unittest.mock import MagicMock

import pytest
import yaml

from dnsmasq.base import DnsmasqBase

from .conftest import make_device, make_dnsmasq_config

DATA = {"dnsmasq_dhcp_hosts__node1": ["aa:bb:cc:dd:ee:ff,node1,192.0.2.10"]}


@pytest.fixture
def mock_logger(monkeypatch):
    """Replace the module-level loguru logger with a MagicMock."""
    logger = MagicMock()
    monkeypatch.setattr("dnsmasq.base.logger", logger)
    return logger


def _base(tmp_path, **overrides):
    return DnsmasqBase(make_dnsmasq_config(tmp_path, **overrides))


class TestWriteDnsmasqToDevice:
    def test_existing_directory_match_writes_inside(self, tmp_path):
        (tmp_path / "host_vars" / "node1").mkdir(parents=True)
        base = _base(tmp_path)

        base.write_dnsmasq_to_device(make_device(1, "node1"), DATA)

        output = tmp_path / "host_vars" / "node1" / "999-netbox-dnsmasq.yml"
        assert output.exists()
        assert yaml.safe_load(output.read_text()) == DATA

    def test_existing_single_file_match_appends_with_separator(self, tmp_path):
        (tmp_path / "host_vars").mkdir(parents=True)
        target = tmp_path / "host_vars" / "node1"
        target.write_text("seed: 1\n")
        base = _base(tmp_path)

        base.write_dnsmasq_to_device(make_device(1, "node1"), DATA)

        content = target.read_text()
        # Prior content is preserved and the new block is appended after the
        # "# NetBox dnsmasq" separator.
        assert content.startswith("seed: 1\n")
        assert "\n# NetBox dnsmasq\n" in content
        assert "dnsmasq_dhcp_hosts__node1" in content

    def test_no_match_creates_directory_and_writes(self, tmp_path):
        (tmp_path / "host_vars").mkdir(parents=True)
        base = _base(tmp_path)

        base.write_dnsmasq_to_device(make_device(1, "node1"), DATA)

        output = tmp_path / "host_vars" / "node1" / "999-netbox-dnsmasq.yml"
        assert output.exists()
        assert yaml.safe_load(output.read_text()) == DATA

    def test_multiple_matches_warns_and_writes_nothing(self, tmp_path, mock_logger):
        (tmp_path / "host_vars" / "node1").mkdir(parents=True)
        (tmp_path / "host_vars" / "node1x").mkdir(parents=True)
        base = _base(tmp_path)

        base.write_dnsmasq_to_device(make_device(1, "node1"), DATA)

        mock_logger.warning.assert_called_once()
        assert not (
            tmp_path / "host_vars" / "node1" / "999-netbox-dnsmasq.yml"
        ).exists()
        assert not (
            tmp_path / "host_vars" / "node1x" / "999-netbox-dnsmasq.yml"
        ).exists()

    def test_inventory_hostname_custom_field_drives_glob_target(self, tmp_path):
        (tmp_path / "host_vars" / "pretty").mkdir(parents=True)
        base = _base(tmp_path)
        device = make_device(1, "raw", custom_fields={"inventory_hostname": "pretty"})

        base.write_dnsmasq_to_device(device, DATA)

        assert (tmp_path / "host_vars" / "pretty" / "999-netbox-dnsmasq.yml").exists()
        assert not (tmp_path / "host_vars" / "raw").exists()
