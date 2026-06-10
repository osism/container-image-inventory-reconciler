# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/interfaces.py.

``InterfaceHandler`` selects the OOB management interface for a device and
caches the result. The tests use the *real* ``CacheManager`` (pure in-memory,
covered by tier 1) so the genuine cache-key round-trip is exercised, plus the
``make_fake_api`` pynetbox stub for the ``dcim.interfaces.filter`` /
``ipam.ip_addresses.filter`` lookups. The exception branch swaps in a
``MagicMock`` whose ``filter`` raises. The module-level ``loguru`` logger is
patched with a ``MagicMock`` only where a log assertion documents the branch.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from cache import CacheManager
from interfaces import InterfaceHandler

from .conftest import make_device, make_fake_api, make_interface, make_ip, make_vlan


@pytest.fixture
def mock_logger(monkeypatch):
    """Replace the module-level loguru logger with a MagicMock."""
    logger = MagicMock()
    monkeypatch.setattr("interfaces.logger", logger)
    return logger


def _managed(id, *, mac="aa:bb:cc:dd:ee:ff", vlan=None):
    """A managed OOB interface: mgmt_only with the managed-by-osism tag."""
    return make_interface(
        id=id,
        mgmt_only=True,
        tags=("managed-by-osism",),
        mac_address=mac,
        untagged_vlan=make_vlan(vlan) if vlan is not None else None,
    )


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestInit:
    def test_default_creates_fresh_cache_manager(self):
        handler = InterfaceHandler(MagicMock())
        assert isinstance(handler.cache, CacheManager)

    def test_passed_cache_manager_is_stored(self):
        cache = CacheManager()
        handler = InterfaceHandler(MagicMock(), cache_manager=cache)
        assert handler.cache is cache


# ---------------------------------------------------------------------------
# get_oob_interface
# ---------------------------------------------------------------------------


class TestGetOobInterface:
    def test_cache_hit_returns_without_api_call(self):
        api = MagicMock()
        handler = InterfaceHandler(api)
        handler.cache.set("oob_interface_1", ("192.0.2.10", "mac", 5))
        assert handler.get_oob_interface(make_device(1, "d1")) == (
            "192.0.2.10",
            "mac",
            5,
        )
        api.dcim.interfaces.filter.assert_not_called()

    def test_ideal_match_returns_ip_mac_vlan_and_caches(self):
        iface = _managed(10, mac="aa:bb:cc:dd:ee:ff", vlan=5)
        api = make_fake_api(
            interfaces=[iface],
            ips_by_interface={10: [make_ip("192.0.2.10/24")]},
        )
        handler = InterfaceHandler(api)
        result = handler.get_oob_interface(make_device(1, "d1"))
        assert result == ("192.0.2.10", "aa:bb:cc:dd:ee:ff", 5)
        assert handler.cache.get("oob_interface_1") == result

    def test_second_call_is_served_from_cache(self):
        iface = _managed(10, mac="aa:bb:cc:dd:ee:ff", vlan=5)
        api = make_fake_api(
            interfaces=[iface],
            ips_by_interface={10: [make_ip("192.0.2.10/24")]},
        )
        handler = InterfaceHandler(api)
        device = make_device(1, "d1")
        first = handler.get_oob_interface(device)
        # Swap in an API that fails if consulted; the cache must answer.
        guard = MagicMock()
        guard.dcim.interfaces.filter.side_effect = AssertionError("API touched")
        handler.api = guard
        assert handler.get_oob_interface(device) == first
        guard.dcim.interfaces.filter.assert_not_called()

    def test_ip_bearing_interface_wins_over_earlier_mac_only(self):
        mac_only = _managed(10, mac="mac-no-ip", vlan=1)
        ip_bearing = _managed(11, mac="mac-with-ip", vlan=2)
        api = make_fake_api(
            interfaces=[mac_only, ip_bearing],
            ips_by_interface={11: [make_ip("203.0.113.5/24")]},
        )
        result = InterfaceHandler(api).get_oob_interface(make_device(1, "d1"))
        assert result == ("203.0.113.5", "mac-with-ip", 2)

    def test_mac_only_fallback_returns_none_ip_and_caches(self, mock_logger):
        iface = _managed(10, mac="mac-1", vlan=7)
        api = make_fake_api(interfaces=[iface], ips_by_interface={})
        handler = InterfaceHandler(api)
        result = handler.get_oob_interface(make_device(1, "d1"))
        assert result == (None, "mac-1", 7)
        assert mock_logger.info.called
        assert handler.cache.get("oob_interface_1") == result

    def test_first_mac_only_fallback_wins(self):
        first = _managed(10, mac="mac-1", vlan=1)
        second = _managed(11, mac="mac-2", vlan=2)
        api = make_fake_api(interfaces=[first, second], ips_by_interface={})
        result = InterfaceHandler(api).get_oob_interface(make_device(1, "d1"))
        assert result == (None, "mac-1", 1)

    def test_non_mgmt_only_interface_is_skipped(self):
        iface = make_interface(
            id=10,
            mgmt_only=False,
            tags=("managed-by-osism",),
            mac_address="mac",
            untagged_vlan=make_vlan(1),
        )
        api = make_fake_api(
            interfaces=[iface],
            ips_by_interface={10: [make_ip("192.0.2.10/24")]},
        )
        assert InterfaceHandler(api).get_oob_interface(make_device(1, "d1")) == (
            None,
            None,
            None,
        )

    def test_interface_without_osism_tag_is_skipped(self):
        iface = make_interface(
            id=10,
            mgmt_only=True,
            tags=("other",),
            mac_address="mac",
            untagged_vlan=make_vlan(1),
        )
        api = make_fake_api(
            interfaces=[iface],
            ips_by_interface={10: [make_ip("192.0.2.10/24")]},
        )
        assert InterfaceHandler(api).get_oob_interface(make_device(1, "d1")) == (
            None,
            None,
            None,
        )

    def test_managed_interface_without_mac_is_skipped(self, mock_logger):
        iface = make_interface(
            id=10,
            mgmt_only=True,
            tags=("managed-by-osism",),
            mac_address=None,
            untagged_vlan=make_vlan(1),
        )
        api = make_fake_api(
            interfaces=[iface],
            ips_by_interface={10: [make_ip("192.0.2.10/24")]},
        )
        result = InterfaceHandler(api).get_oob_interface(make_device(1, "d1"))
        assert result == (None, None, None)
        assert mock_logger.debug.called

    def test_no_interfaces_returns_none_tuple_and_caches(self):
        api = make_fake_api(interfaces=[], ips_by_interface={})
        handler = InterfaceHandler(api)
        result = handler.get_oob_interface(make_device(1, "d1"))
        assert result == (None, None, None)
        # The negative result is cached (the tuple is not None).
        assert handler.cache.get("oob_interface_1") == (None, None, None)

    def test_vlan_id_is_extracted_into_result(self):
        iface = _managed(10, mac="mac", vlan=42)
        api = make_fake_api(
            interfaces=[iface],
            ips_by_interface={10: [make_ip("192.0.2.10/24")]},
        )
        result = InterfaceHandler(api).get_oob_interface(make_device(1, "d1"))
        assert result[2] == 42

    def test_filter_exception_returns_none_tuple_without_caching(self, mock_logger):
        api = MagicMock()
        api.dcim.interfaces.filter.side_effect = RuntimeError("boom")
        handler = InterfaceHandler(api)
        device = make_device(1, "d1")
        assert handler.get_oob_interface(device) == (None, None, None)
        assert mock_logger.warning.called
        # The except path skips cache.set, so the result is not cached...
        assert handler.cache.get("oob_interface_1") is None
        # ...and a subsequent call queries the API again.
        handler.get_oob_interface(device)
        assert api.dcim.interfaces.filter.call_count == 2


# ---------------------------------------------------------------------------
# _is_managed_oob_interface
#
# Unlike the gnmic_extractor twin (#543), this reads interface.tags directly
# with no hasattr guard -- interface stubs must always define tags.
# ---------------------------------------------------------------------------


class TestIsManagedOobInterface:
    @staticmethod
    def _handler():
        return InterfaceHandler(MagicMock())

    def test_empty_tags_returns_false(self):
        iface = make_interface(id=1, mgmt_only=True, tags=())
        assert self._handler()._is_managed_oob_interface(iface) is False

    def test_falsy_tags_returns_false(self):
        iface = SimpleNamespace(tags=None, mgmt_only=True)
        assert self._handler()._is_managed_oob_interface(iface) is False

    def test_not_mgmt_only_returns_false(self):
        iface = make_interface(id=1, mgmt_only=False, tags=("managed-by-osism",))
        assert self._handler()._is_managed_oob_interface(iface) is False

    def test_mgmt_only_without_osism_tag_returns_false(self):
        iface = make_interface(id=1, mgmt_only=True, tags=("other",))
        assert self._handler()._is_managed_oob_interface(iface) is False

    def test_mgmt_only_with_osism_tag_among_others_returns_true(self):
        iface = make_interface(id=1, mgmt_only=True, tags=("other", "managed-by-osism"))
        assert self._handler()._is_managed_oob_interface(iface) is True

    def test_interface_without_tags_attribute_raises(self):
        iface = SimpleNamespace(mgmt_only=True)  # no tags attribute at all
        with pytest.raises(AttributeError):
            self._handler()._is_managed_oob_interface(iface)


# ---------------------------------------------------------------------------
# _get_vlan_id
# ---------------------------------------------------------------------------


class TestGetVlanId:
    @staticmethod
    def _handler():
        return InterfaceHandler(MagicMock())

    def test_untagged_vlan_with_vid_returns_vid(self):
        iface = make_interface(id=1, untagged_vlan=make_vlan(100))
        assert self._handler()._get_vlan_id(iface) == 100

    def test_untagged_vlan_none_returns_none(self):
        iface = make_interface(id=1, untagged_vlan=None)
        assert self._handler()._get_vlan_id(iface) is None

    def test_missing_untagged_vlan_attribute_returns_none(self):
        iface = SimpleNamespace()  # no untagged_vlan attribute -> hasattr guard
        assert self._handler()._get_vlan_id(iface) is None


# ---------------------------------------------------------------------------
# _get_interface_ip
# ---------------------------------------------------------------------------


class TestGetInterfaceIp:
    def test_first_ip_has_mask_stripped(self):
        api = make_fake_api(ips_by_interface={1: [make_ip("10.0.0.5/24")]})
        assert InterfaceHandler(api)._get_interface_ip(make_interface(id=1)) == (
            "10.0.0.5"
        )

    def test_only_first_ip_is_returned(self):
        api = make_fake_api(
            ips_by_interface={1: [make_ip("10.0.0.5/24"), make_ip("10.0.0.6/24")]}
        )
        assert InterfaceHandler(api)._get_interface_ip(make_interface(id=1)) == (
            "10.0.0.5"
        )

    def test_no_ips_returns_none(self):
        api = make_fake_api(ips_by_interface={})
        assert InterfaceHandler(api)._get_interface_ip(make_interface(id=1)) is None

    def test_filter_called_with_interface_id(self):
        api = MagicMock()
        api.ipam.ip_addresses.filter.return_value = [make_ip("10.0.0.5/24")]
        assert InterfaceHandler(api)._get_interface_ip(make_interface(id=7)) == (
            "10.0.0.5"
        )
        api.ipam.ip_addresses.filter.assert_called_once_with(interface_id=7)


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
