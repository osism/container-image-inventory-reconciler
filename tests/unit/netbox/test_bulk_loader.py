# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/bulk_loader.py.

``BulkDataLoader`` wraps the pynetbox session: it loads interfaces and IP
addresses in batches, caches them, and serves them back grouped by device /
interface id. The tests use a ``MagicMock`` API (rather than ``make_fake_api``)
because the per-batch ``call_args_list`` and per-call ``side_effect`` failures
are exactly what the batching / error-handling branches need to assert. No live
NetBox is involved.

Interface stubs carry ``.id`` and ``.device.id`` (built with ``make_interface``
plus a ``SimpleNamespace`` device); IP stubs carry ``.assigned_object_id``
(built with ``make_ip``). The error-path test deliberately uses an interface
stub *without* a ``device`` attribute so the grouping loop raises.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, call

import pytest

from bulk_loader import BulkDataLoader

from .conftest import make_interface, make_ip


def _iface(id, device_id):
    """An interface stub exposing the ``.id`` / ``.device.id`` bulk_loader reads."""
    return make_interface(id=id, device=SimpleNamespace(id=device_id))


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestInit:
    def test_defaults(self):
        loader = BulkDataLoader(MagicMock())
        assert loader.batch_size == 100
        assert loader.device_interfaces == {}
        assert loader.interface_ips == {}

    def test_custom_batch_size_is_stored(self):
        loader = BulkDataLoader(MagicMock(), batch_size=25)
        assert loader.batch_size == 25

    def test_class_constant_matches_default(self):
        assert BulkDataLoader.BATCH_SIZE == 100
        assert BulkDataLoader(MagicMock()).batch_size == BulkDataLoader.BATCH_SIZE


# ---------------------------------------------------------------------------
# _chunk_list
# ---------------------------------------------------------------------------


class TestChunkList:
    def test_empty_list(self):
        assert BulkDataLoader._chunk_list([], 3) == []

    def test_smaller_than_chunk_size(self):
        assert BulkDataLoader._chunk_list([1, 2], 3) == [[1, 2]]

    def test_exactly_chunk_size(self):
        assert BulkDataLoader._chunk_list([1, 2, 3], 3) == [[1, 2, 3]]

    def test_one_over_chunk_size(self):
        assert BulkDataLoader._chunk_list([1, 2, 3, 4], 3) == [[1, 2, 3], [4]]

    def test_exact_multiple_has_no_trailing_empty_chunk(self):
        assert BulkDataLoader._chunk_list([1, 2, 3, 4, 5, 6], 3) == [
            [1, 2, 3],
            [4, 5, 6],
        ]

    def test_chunk_size_one_yields_one_chunk_per_item(self):
        assert BulkDataLoader._chunk_list([1, 2, 3], 1) == [[1], [2], [3]]

    def test_order_preserved_round_trips(self):
        items = list(range(10))
        chunks = BulkDataLoader._chunk_list(items, 3)
        assert [item for chunk in chunks for item in chunk] == items


# ---------------------------------------------------------------------------
# load_device_data
# ---------------------------------------------------------------------------


class TestLoadDeviceData:
    def test_empty_device_ids_makes_no_api_call(self):
        api = MagicMock()
        loader = BulkDataLoader(api)
        loader.load_device_data([])
        api.dcim.interfaces.filter.assert_not_called()
        assert loader.device_interfaces == {}
        assert loader.interface_ips == {}

    def test_single_batch_groups_interfaces_by_device(self):
        api = MagicMock()
        i10, i11, i20 = _iface(10, 1), _iface(11, 1), _iface(20, 2)
        api.dcim.interfaces.filter.return_value = [i10, i11, i20]
        api.ipam.ip_addresses.filter.return_value = []
        loader = BulkDataLoader(api)
        loader.load_device_data([1, 2, 3])
        api.dcim.interfaces.filter.assert_called_once_with(device_id=[1, 2, 3])
        assert loader.device_interfaces == {1: [i10, i11], 2: [i20]}

    def test_multi_batch_interface_calls_use_correct_chunks(self):
        api = MagicMock()
        api.dcim.interfaces.filter.side_effect = [[], [], []]
        loader = BulkDataLoader(api, batch_size=2)
        loader.load_device_data([1, 2, 3, 4, 5])
        assert api.dcim.interfaces.filter.call_args_list == [
            call(device_id=[1, 2]),
            call(device_id=[3, 4]),
            call(device_id=[5]),
        ]
        # No interfaces returned -> the IP lookup is never reached.
        api.ipam.ip_addresses.filter.assert_not_called()

    def test_ip_addresses_are_batched_and_grouped(self):
        api = MagicMock()
        i10, i11, i12 = _iface(10, 1), _iface(11, 1), _iface(12, 1)
        api.dcim.interfaces.filter.return_value = [i10, i11, i12]
        ip10 = make_ip("10.0.0.1/24", assigned_object_id=10)
        ip11 = make_ip("10.0.0.2/24", assigned_object_id=11)
        ip12 = make_ip("10.0.0.3/24", assigned_object_id=12)
        api.ipam.ip_addresses.filter.side_effect = [[ip10, ip11], [ip12]]
        loader = BulkDataLoader(api, batch_size=2)
        loader.load_device_data([1])
        assert api.ipam.ip_addresses.filter.call_args_list == [
            call(interface_id=[10, 11]),
            call(interface_id=[12]),
        ]
        assert loader.interface_ips == {10: [ip10], 11: [ip11], 12: [ip12]}

    def test_partial_interface_batch_failure_continues(self):
        api = MagicMock()
        i_a, i_c = _iface(10, 1), _iface(30, 3)
        api.dcim.interfaces.filter.side_effect = [[i_a], Exception("boom"), [i_c]]
        api.ipam.ip_addresses.filter.return_value = []
        loader = BulkDataLoader(api, batch_size=1)
        loader.load_device_data([1, 2, 3])  # second batch raises, no propagation
        assert loader.device_interfaces == {1: [i_a], 3: [i_c]}

    def test_partial_ip_batch_failure_continues(self):
        api = MagicMock()
        i10, i11, i12 = _iface(10, 1), _iface(11, 1), _iface(12, 1)
        api.dcim.interfaces.filter.return_value = [i10, i11, i12]
        ip10 = make_ip("10.0.0.1/24", assigned_object_id=10)
        ip12 = make_ip("10.0.0.3/24", assigned_object_id=12)
        api.ipam.ip_addresses.filter.side_effect = [[ip10], Exception("boom"), [ip12]]
        loader = BulkDataLoader(api, batch_size=1)
        loader.load_device_data([1])  # second IP batch raises, no propagation
        assert loader.interface_ips == {10: [ip10], 12: [ip12]}

    def test_no_interfaces_skips_ip_loading(self):
        api = MagicMock()
        api.dcim.interfaces.filter.return_value = []
        loader = BulkDataLoader(api)
        loader.load_device_data([1, 2])
        api.ipam.ip_addresses.filter.assert_not_called()
        assert loader.device_interfaces == {}
        assert loader.interface_ips == {}

    def test_interface_without_ips_is_absent_from_cache(self):
        api = MagicMock()
        i10 = _iface(10, 1)
        api.dcim.interfaces.filter.return_value = [i10]
        api.ipam.ip_addresses.filter.return_value = []
        loader = BulkDataLoader(api)
        loader.load_device_data([1])
        assert loader.interface_ips == {}
        assert loader.get_interface_ip_addresses(i10) == []

    def test_grouping_error_clears_state_and_reraises(self):
        api = MagicMock()
        # Interface stub WITHOUT a .device attribute: interface.device.id in
        # the grouping loop raises AttributeError, caught by the outer except.
        api.dcim.interfaces.filter.return_value = [SimpleNamespace(id=1)]
        loader = BulkDataLoader(api)
        # Pre-seed both caches to prove the error path clears them.
        loader.device_interfaces[99] = ["stale"]
        loader.interface_ips[99] = ["stale"]
        with pytest.raises(AttributeError):
            loader.load_device_data([1])
        assert loader.device_interfaces == {}
        assert loader.interface_ips == {}

    def test_successive_loads_accumulate(self):
        api = MagicMock()
        i10, i20 = _iface(10, 1), _iface(20, 2)
        api.dcim.interfaces.filter.side_effect = [[i10], [i20]]
        api.ipam.ip_addresses.filter.return_value = []
        loader = BulkDataLoader(api)
        loader.load_device_data([1])
        loader.load_device_data([2])
        # Caches are additive across calls, not reset per call.
        assert loader.device_interfaces == {1: [i10], 2: [i20]}


# ---------------------------------------------------------------------------
# get_device_interfaces
# ---------------------------------------------------------------------------


class TestGetDeviceInterfaces:
    def test_known_device_returns_its_interfaces(self):
        loader = BulkDataLoader(MagicMock())
        i10 = _iface(10, 1)
        loader.device_interfaces[1] = [i10]
        assert loader.get_device_interfaces(SimpleNamespace(id=1)) == [i10]

    def test_unknown_device_returns_empty_list(self):
        loader = BulkDataLoader(MagicMock())
        assert loader.get_device_interfaces(SimpleNamespace(id=999)) == []


# ---------------------------------------------------------------------------
# get_interface_ip_addresses
# ---------------------------------------------------------------------------


class TestGetInterfaceIpAddresses:
    def test_known_interface_returns_its_ips(self):
        loader = BulkDataLoader(MagicMock())
        ip = make_ip("10.0.0.1/24", assigned_object_id=10)
        loader.interface_ips[10] = [ip]
        assert loader.get_interface_ip_addresses(SimpleNamespace(id=10)) == [ip]

    def test_unknown_interface_returns_empty_list(self):
        loader = BulkDataLoader(MagicMock())
        assert loader.get_interface_ip_addresses(SimpleNamespace(id=999)) == []


# ---------------------------------------------------------------------------
# clear
# ---------------------------------------------------------------------------


class TestClear:
    def test_clear_empties_both_caches(self):
        api = MagicMock()
        i10 = _iface(10, 1)
        api.dcim.interfaces.filter.return_value = [i10]
        api.ipam.ip_addresses.filter.return_value = [
            make_ip("10.0.0.1/24", assigned_object_id=10)
        ]
        loader = BulkDataLoader(api)
        loader.load_device_data([1])
        loader.clear()
        assert loader.device_interfaces == {}
        assert loader.interface_ips == {}
        assert loader.get_device_interfaces(SimpleNamespace(id=1)) == []
        assert loader.get_interface_ip_addresses(i10) == []


# ---------------------------------------------------------------------------
# get_statistics
# ---------------------------------------------------------------------------


class TestGetStatistics:
    def test_fresh_loader_reports_zero_counts(self):
        loader = BulkDataLoader(MagicMock())
        assert loader.get_statistics() == {
            "devices": 0,
            "interfaces": 0,
            "ip_addresses": 0,
        }

    def test_counts_sum_across_devices_and_interfaces(self):
        api = MagicMock()
        i10, i11, i20 = _iface(10, 1), _iface(11, 1), _iface(20, 2)
        api.dcim.interfaces.filter.return_value = [i10, i11, i20]
        api.ipam.ip_addresses.filter.return_value = [
            make_ip("10.0.0.1/24", assigned_object_id=10),
            make_ip("10.0.0.2/24", assigned_object_id=11),
            make_ip("10.0.0.3/24", assigned_object_id=20),
        ]
        loader = BulkDataLoader(api)
        loader.load_device_data([1, 2])  # 2 devices, 2+1 interfaces, 3 IPs
        assert loader.get_statistics() == {
            "devices": 2,
            "interfaces": 3,
            "ip_addresses": 3,
        }


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
