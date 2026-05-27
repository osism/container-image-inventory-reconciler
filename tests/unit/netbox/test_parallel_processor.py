# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/parallel_processor.py.

The parallel branch runs a real ``ThreadPoolExecutor`` with a trivial
``process_func`` -- thread overhead is negligible at this scale and the test
exercises the actual concurrent code path rather than a stubbed-out one.
"""

from unittest.mock import MagicMock

import pytest

from parallel_processor import ParallelDeviceProcessor

from .conftest import make_device

# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestInit:
    def test_defaults(self):
        p = ParallelDeviceProcessor()
        assert p.max_workers == 10
        assert p.enabled is True
        assert p.results == {}
        assert p.failures == []

    def test_custom_values_are_stored(self):
        p = ParallelDeviceProcessor(max_workers=4, enabled=False)
        assert p.max_workers == 4
        assert p.enabled is False


# ---------------------------------------------------------------------------
# process_devices dispatch
# ---------------------------------------------------------------------------


class TestProcessDevicesDispatch:
    def test_disabled_dispatches_to_sequential(self, monkeypatch):
        p = ParallelDeviceProcessor(enabled=False, max_workers=10)
        seq = MagicMock(return_value="seq")
        par = MagicMock(return_value="par")
        monkeypatch.setattr(p, "_process_sequential", seq)
        monkeypatch.setattr(p, "_process_parallel", par)

        assert p.process_devices([], lambda d: None) == "seq"
        par.assert_not_called()

    def test_max_workers_one_dispatches_to_sequential(self, monkeypatch):
        # ``max_workers=1`` short-circuits to the sequential branch even when
        # parallel processing is enabled -- the ``or`` clause in the dispatch.
        p = ParallelDeviceProcessor(enabled=True, max_workers=1)
        seq = MagicMock(return_value="seq")
        par = MagicMock(return_value="par")
        monkeypatch.setattr(p, "_process_sequential", seq)
        monkeypatch.setattr(p, "_process_parallel", par)

        assert p.process_devices([], lambda d: None) == "seq"
        par.assert_not_called()

    def test_enabled_with_multiple_workers_dispatches_to_parallel(self, monkeypatch):
        p = ParallelDeviceProcessor(enabled=True, max_workers=4)
        seq = MagicMock(return_value="seq")
        par = MagicMock(return_value="par")
        monkeypatch.setattr(p, "_process_sequential", seq)
        monkeypatch.setattr(p, "_process_parallel", par)

        assert p.process_devices([], lambda d: None) == "par"
        seq.assert_not_called()

    @pytest.mark.parametrize("enabled,max_workers", [(False, 10), (True, 1), (True, 4)])
    def test_empty_devices_returns_zero_counts(self, enabled, max_workers):
        p = ParallelDeviceProcessor(enabled=enabled, max_workers=max_workers)
        result = p.process_devices([], lambda d: None)
        assert result == {
            "completed": 0,
            "failed": 0,
            "results": {},
            "failures": [],
        }

    @pytest.mark.parametrize(
        "enabled,max_workers",
        [(False, 10), (True, 1), (True, 4)],
        ids=["sequential", "single-worker", "parallel"],
    )
    def test_public_dispatch_forwards_args_and_kwargs(self, enabled, max_workers):
        # Exercise the real ``*args, **kwargs`` forwarding through the public
        # dispatch -- the monkeypatched tests above never execute lines 44/46
        # of parallel_processor.py.
        p = ParallelDeviceProcessor(enabled=enabled, max_workers=max_workers)
        d = make_device(1, "d1")
        captured = []

        def func(device, marker, *, flag):
            captured.append((device.id, marker, flag))
            return device.id

        p.process_devices([d], func, "x", flag=True)

        assert captured == [(1, "x", True)]


# ---------------------------------------------------------------------------
# _process_sequential
# ---------------------------------------------------------------------------


class TestProcessSequential:
    def test_all_devices_succeed(self):
        p = ParallelDeviceProcessor(enabled=False)
        devices = [make_device(i, f"d{i}") for i in range(1, 4)]
        result = p._process_sequential(devices, lambda d: d.id * 10)
        assert result["completed"] == 3
        assert result["failed"] == 0
        assert result["results"] == {"d1": 10, "d2": 20, "d3": 30}
        assert result["failures"] == []

    def test_failure_captures_full_metadata(self):
        p = ParallelDeviceProcessor(enabled=False)
        bad = make_device(7, "bad")

        def boom(device):
            raise RuntimeError("kaboom")

        result = p._process_sequential([bad], boom)
        assert result["failed"] == 1
        assert result["completed"] == 0
        assert result["failures"] == [
            {
                "device": "bad",
                "device_id": 7,
                "error": "kaboom",
                "error_type": "RuntimeError",
            }
        ]

    def test_one_failure_does_not_abort_subsequent_devices(self):
        p = ParallelDeviceProcessor(enabled=False)
        d1 = make_device(1, "d1")
        d2 = make_device(2, "d2")
        d3 = make_device(3, "d3")

        def func(device):
            if device.id == 2:
                raise ValueError("middle")
            return device.id

        result = p._process_sequential([d1, d2, d3], func)
        assert result["completed"] == 2
        assert result["failed"] == 1
        assert result["results"] == {"d1": 1, "d3": 3}
        assert result["failures"][0]["device"] == "d2"
        assert result["failures"][0]["error_type"] == "ValueError"

    def test_args_and_kwargs_forwarded(self):
        p = ParallelDeviceProcessor(enabled=False)
        d = make_device(1, "d1")
        func = MagicMock(return_value="ok")

        p._process_sequential([d], func, "x", flag=True)

        func.assert_called_once_with(d, "x", flag=True)

    def test_progress_logged_at_tenth_and_final_completion(self, monkeypatch):
        # With 11 devices the progress message fires at completed==10
        # (% 10 == 0) and again at completed==11 (== len(devices)).
        p = ParallelDeviceProcessor(enabled=False)
        devices = [make_device(i, f"d{i}") for i in range(1, 12)]

        mock_logger = MagicMock()
        monkeypatch.setattr("parallel_processor.logger", mock_logger)

        p._process_sequential(devices, lambda d: d.id)

        progress_logs = [
            call
            for call in mock_logger.info.call_args_list
            if call.args and "Progress:" in call.args[0]
        ]
        assert len(progress_logs) == 2
        assert "10/11" in progress_logs[0].args[0]
        assert "11/11" in progress_logs[1].args[0]


# ---------------------------------------------------------------------------
# _process_parallel
# ---------------------------------------------------------------------------


class TestProcessParallel:
    def test_all_devices_succeed(self):
        p = ParallelDeviceProcessor(enabled=True, max_workers=2)
        devices = [make_device(i, f"d{i}") for i in range(1, 6)]

        result = p._process_parallel(devices, lambda d: d.id)

        assert result["completed"] == 5
        assert result["failed"] == 0
        # Ordering is non-deterministic under ``as_completed`` -- compare on
        # the key set rather than the list of items.
        assert set(result["results"].keys()) == {f"d{i}" for i in range(1, 6)}
        assert result["results"] == {f"d{i}": i for i in range(1, 6)}
        assert result["failures"] == []

    def test_one_failure_captured_others_complete(self):
        p = ParallelDeviceProcessor(enabled=True, max_workers=2)
        devices = [make_device(i, f"d{i}") for i in range(1, 6)]

        def func(device):
            if device.id == 3:
                raise RuntimeError("middle")
            return device.id

        result = p._process_parallel(devices, func)

        assert result["completed"] == 4
        assert result["failed"] == 1
        assert "d3" not in result["results"]
        assert set(result["results"].keys()) == {"d1", "d2", "d4", "d5"}
        assert len(result["failures"]) == 1
        failure = result["failures"][0]
        assert failure == {
            "device": "d3",
            "device_id": 3,
            "error": "middle",
            "error_type": "RuntimeError",
        }

    def test_args_and_kwargs_forwarded(self):
        p = ParallelDeviceProcessor(enabled=True, max_workers=2)
        devices = [make_device(1, "d1"), make_device(2, "d2")]
        captured = []

        def func(device, marker, *, flag):
            captured.append((device.id, marker, flag))
            return device.id

        p._process_parallel(devices, func, "x", flag=True)

        assert sorted(captured) == [(1, "x", True), (2, "x", True)]


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
