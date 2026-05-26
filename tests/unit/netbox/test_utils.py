# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/utils.py."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import utils

from .conftest import FakeSettings


class TestGetInventoryHostname:
    def test_custom_field_string_is_returned(self):
        device = SimpleNamespace(
            name="fallback-name",
            custom_fields={"inventory_hostname": "custom-host"},
        )
        assert utils.get_inventory_hostname(device) == "custom-host"

    def test_custom_field_non_string_is_coerced_to_str(self):
        device = SimpleNamespace(
            name="fallback-name",
            custom_fields={"inventory_hostname": 12345},
        )
        assert utils.get_inventory_hostname(device) == "12345"

    @pytest.mark.parametrize("value", ["", None])
    def test_empty_or_none_custom_field_falls_back_to_name(self, value):
        device = SimpleNamespace(
            name="fallback-name",
            custom_fields={"inventory_hostname": value},
        )
        assert utils.get_inventory_hostname(device) == "fallback-name"

    def test_missing_custom_field_falls_back_to_name(self):
        device = SimpleNamespace(name="fallback-name", custom_fields={})
        assert utils.get_inventory_hostname(device) == "fallback-name"

    def test_none_custom_fields_falls_back_to_name(self):
        # device.custom_fields is None -> the `or {}` branch keeps .get() safe
        device = SimpleNamespace(name="fallback-name", custom_fields=None)
        assert utils.get_inventory_hostname(device) == "fallback-name"

    def test_non_string_device_name_is_coerced_to_str(self):
        device = SimpleNamespace(name=42, custom_fields={})
        assert utils.get_inventory_hostname(device) == "42"


class TestDeepMerge:
    def test_disjoint_keys_are_unioned(self):
        assert utils.deep_merge({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}

    def test_overlapping_non_dict_keys_override_wins(self):
        # override wins even when the value types differ (int vs str)
        assert utils.deep_merge({"a": 1}, {"a": "two"}) == {"a": "two"}

    def test_overlapping_dict_keys_are_merged_recursively(self):
        base = {"a": {"x": 1}}
        override = {"a": {"y": 2}}
        assert utils.deep_merge(base, override) == {"a": {"x": 1, "y": 2}}

    def test_dict_base_with_list_override_is_replaced(self):
        assert utils.deep_merge({"a": {"x": 1}}, {"a": [1, 2]}) == {"a": [1, 2]}

    def test_list_base_with_dict_override_is_replaced(self):
        assert utils.deep_merge({"a": [1, 2]}, {"a": {"x": 1}}) == {"a": {"x": 1}}

    def test_lists_at_same_key_are_replaced_not_concatenated(self):
        assert utils.deep_merge({"a": [1, 2]}, {"a": [3]}) == {"a": [3]}

    def test_base_is_not_mutated(self):
        base = {"a": {"x": 1}, "b": 2}
        result = utils.deep_merge(base, {"a": {"y": 9}, "b": 3})
        assert base == {"a": {"x": 1}, "b": 2}
        assert result is not base

    def test_both_inputs_empty_returns_empty_dict(self):
        assert utils.deep_merge({}, {}) == {}


class TestSetupLogging:
    def test_default_level_is_info(self, monkeypatch):
        mock_logger = MagicMock()
        monkeypatch.setattr(utils, "logger", mock_logger)
        monkeypatch.setattr(utils, "SETTINGS", FakeSettings({}))

        utils.setup_logging()

        assert mock_logger.add.call_args.kwargs["level"] == "INFO"

    def test_debug_level_from_settings(self, monkeypatch):
        mock_logger = MagicMock()
        monkeypatch.setattr(utils, "logger", mock_logger)
        monkeypatch.setattr(
            utils, "SETTINGS", FakeSettings({"OSISM_LOG_LEVEL": "DEBUG"})
        )

        utils.setup_logging()

        assert mock_logger.add.call_args.kwargs["level"] == "DEBUG"

    def test_remove_is_called_before_add(self, monkeypatch):
        mock_logger = MagicMock()
        monkeypatch.setattr(utils, "logger", mock_logger)
        monkeypatch.setattr(utils, "SETTINGS", FakeSettings({}))

        utils.setup_logging()

        method_names = [c[0] for c in mock_logger.method_calls]
        assert method_names == ["remove", "add"]

    def test_repeated_calls_are_idempotent(self, monkeypatch):
        # Each call drops existing handlers first, so remove() and add() stay
        # balanced no matter how many times setup_logging() runs.
        mock_logger = MagicMock()
        monkeypatch.setattr(utils, "logger", mock_logger)
        monkeypatch.setattr(utils, "SETTINGS", FakeSettings({}))

        utils.setup_logging()
        utils.setup_logging()

        assert mock_logger.remove.call_count == 2
        assert mock_logger.add.call_count == 2
