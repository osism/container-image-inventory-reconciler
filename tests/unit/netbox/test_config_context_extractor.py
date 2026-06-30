# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/extractors/config_context_extractor.py.

The extractor copies ``device.config_context`` into a new dict, dropping the
``frr_parameters`` / ``netplan_parameters`` / ``ceph_parameters`` keys
(handled by their dedicated extractors) and the empty-string key. Non-dict
values pass straight through.
"""

import pytest

from extractors.config_context_extractor import ConfigContextExtractor

from .conftest import make_device


def _device(ctx):
    """Build a device exposing the ``config_context`` attribute."""
    device = make_device(1, "node1")
    device.config_context = ctx
    return device


class TestExtract:
    def test_strips_frr_and_netplan_keeps_rest(self):
        ctx = {
            "frr_parameters": {"frr_local_as": 1},
            "netplan_parameters": {"network_ethernets": {}},
            "ceph_parameters": {"ceph_osd_devices": ["/dev/sdb"]},
            "ntp_servers": ["a", "b"],
            "foo": 1,
        }
        result = ConfigContextExtractor().extract(_device(ctx))
        assert result == {"ntp_servers": ["a", "b"], "foo": 1}

    def test_strips_empty_string_key(self):
        ctx = {"": "junk", "keep": 1}
        assert ConfigContextExtractor().extract(_device(ctx)) == {"keep": 1}

    def test_unfiltered_dict_is_copied_not_mutated(self):
        ctx = {"a": 1, "b": 2}
        result = ConfigContextExtractor().extract(_device(ctx))
        assert result == {"a": 1, "b": 2}
        # The comprehension returns a new dict; the original is left untouched.
        assert result is not ctx
        assert ctx == {"a": 1, "b": 2}

    def test_only_filtered_keys_returns_empty_dict(self):
        ctx = {
            "frr_parameters": 1,
            "netplan_parameters": 2,
            "ceph_parameters": 4,
            "": 3,
        }
        assert ConfigContextExtractor().extract(_device(ctx)) == {}

    @pytest.mark.parametrize("ctx", [None, ["a", "b"], "a string"])
    def test_non_dict_passed_through_unchanged(self, ctx):
        assert ConfigContextExtractor().extract(_device(ctx)) is ctx

    def test_empty_dict_returns_empty_dict(self):
        assert ConfigContextExtractor().extract(_device({})) == {}

    def test_extra_kwargs_are_ignored(self):
        ctx = {"keep": 1, "frr_parameters": 2}
        assert ConfigContextExtractor().extract(_device(ctx), unused="x") == {"keep": 1}


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
