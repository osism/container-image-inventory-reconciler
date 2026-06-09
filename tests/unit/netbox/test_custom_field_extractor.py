# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/extractors/custom_field_extractor.py.

The extractor requires a ``field_name`` and returns ``device.custom_fields``
(coerced to ``{}`` when falsy) looked up by that name, or ``None`` on a miss.
"""

import pytest

from extractors.custom_field_extractor import CustomFieldExtractor

from .conftest import make_device


class TestExtract:
    def test_field_name_omitted_raises(self):
        device = make_device(1, "node1", custom_fields={"a": 1})
        with pytest.raises(ValueError, match="field_name parameter is required"):
            CustomFieldExtractor().extract(device)

    @pytest.mark.parametrize("field_name", [None, ""])
    def test_falsy_field_name_raises(self, field_name):
        device = make_device(1, "node1", custom_fields={"a": 1})
        with pytest.raises(ValueError, match="field_name parameter is required"):
            CustomFieldExtractor().extract(device, field_name=field_name)

    @pytest.mark.parametrize("value", [0, False, "", "value", 42])
    def test_present_field_returns_value_including_falsy(self, value):
        device = make_device(1, "node1", custom_fields={"target": value})
        assert CustomFieldExtractor().extract(device, field_name="target") == value

    def test_absent_field_returns_none(self):
        device = make_device(1, "node1", custom_fields={"other": 1})
        assert CustomFieldExtractor().extract(device, field_name="target") is None

    def test_none_custom_fields_coerced_to_empty(self):
        device = make_device(1, "node1", custom_fields=None)
        assert CustomFieldExtractor().extract(device, field_name="target") is None

    def test_empty_custom_fields_returns_none(self):
        device = make_device(1, "node1", custom_fields={})
        assert CustomFieldExtractor().extract(device, field_name="target") is None

    def test_nested_value_returned_by_reference(self):
        nested = {"a": [1, 2], "b": {"c": 3}}
        device = make_device(1, "node1", custom_fields={"target": nested})
        result = CustomFieldExtractor().extract(device, field_name="target")
        assert result is nested

    def test_extra_kwargs_are_ignored(self):
        device = make_device(1, "node1", custom_fields={"target": "v"})
        result = CustomFieldExtractor().extract(device, field_name="target", unused="x")
        assert result == "v"


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
