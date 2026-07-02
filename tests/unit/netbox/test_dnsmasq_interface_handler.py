# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/dnsmasq/interface_handler.py.

``InterfaceHandler.get_virtual_interfaces_for_dnsmasq`` is a static method that
selects virtual interfaces carrying the ``managed-by-osism`` tag and an
untagged VLAN, returning the label (preferred) or name of each. Interfaces are
read through a pynetbox session faked by ``make_fake_api`` (plain lists) or, for
the filter-raises branch, a ``MagicMock`` with a ``side_effect``. The
module-level ``loguru`` logger is patched only where a log assertion documents
the branch taken.

Note: this is ``dnsmasq.interface_handler.InterfaceHandler`` -- distinct from
the unrelated ``interfaces.InterfaceHandler`` class elsewhere in the package.
"""

from unittest.mock import MagicMock

import pytest

from dnsmasq.interface_handler import InterfaceHandler

from .conftest import (
    make_device,
    make_fake_api,
    make_iface_type,
    make_interface,
    make_vlan,
)


@pytest.fixture
def mock_logger(monkeypatch):
    """Replace the module-level loguru logger with a MagicMock."""
    logger = MagicMock()
    monkeypatch.setattr("dnsmasq.interface_handler.logger", logger)
    return logger


def _virtual(**overrides):
    """A qualifying virtual interface (managed-by-osism + untagged VLAN)."""
    params = dict(
        id=1,
        type=make_iface_type("virtual"),
        tags=("managed-by-osism",),
        untagged_vlan=make_vlan(100),
        label="oob1",
        name="eth0",
    )
    params.update(overrides)
    return make_interface(**params)


def _call(interfaces, client=None):
    device = make_device(1, "d1")
    if client is None:
        client = MagicMock()
        client.api = make_fake_api(interfaces=interfaces)
    return InterfaceHandler.get_virtual_interfaces_for_dnsmasq(device, client)


class TestGetVirtualInterfacesForDnsmasq:
    def test_filter_raises_warns_and_returns_empty(self, mock_logger):
        client = MagicMock()
        client.api.dcim.interfaces.filter.side_effect = Exception("boom")

        result = InterfaceHandler.get_virtual_interfaces_for_dnsmasq(
            make_device(1, "d1"), client
        )

        assert result == []
        mock_logger.warning.assert_called_once()

    def test_no_interfaces_returns_empty(self):
        assert _call([]) == []

    def test_non_virtual_interface_skipped(self):
        iface = _virtual(type=make_iface_type("1000base-t"))
        assert _call([iface]) == []

    def test_virtual_without_tags_skipped(self):
        assert _call([_virtual(tags=())]) == []

    def test_virtual_without_managed_tag_skipped(self):
        assert _call([_virtual(tags=("other",))]) == []

    def test_virtual_managed_without_untagged_vlan_skipped(self):
        assert _call([_virtual(untagged_vlan=None)]) == []

    def test_qualifying_interface_prefers_label_and_debug_logs_vid(self, mock_logger):
        result = _call([_virtual(label="oob1", name="eth0")])

        assert result == ["oob1"]
        mock_logger.debug.assert_called_once()
        message = mock_logger.debug.call_args.args[0]
        assert "oob1" in message and "100" in message

    def test_qualifying_interface_falls_back_to_name(self):
        assert _call([_virtual(label=None, name="eth0")]) == ["eth0"]

    def test_multiple_qualifying_interfaces_preserve_order(self):
        iface1 = _virtual(id=1, label="oob1")
        iface2 = _virtual(id=2, label="oob2")
        assert _call([iface1, iface2]) == ["oob1", "oob2"]
