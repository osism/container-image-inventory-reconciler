# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/filters.py.

``DeviceFilter`` only reads four attributes off its ``Config``-shaped
collaborator (``filter_inventory``, ``reconciler_mode``,
``ignore_provision_state``, ``ignore_maintenance_state``), so the tests
substitute a ``SimpleNamespace`` instead of constructing the real dataclass.
Device-shaped stubs come from the ``make_device`` / ``make_tag`` factories
in ``conftest``.
"""

from types import SimpleNamespace

import pytest

from filters import DeviceFilter

from .conftest import make_device


def _config(
    *,
    filter_inventory=None,
    reconciler_mode="manager",
    ignore_provision_state=False,
    ignore_maintenance_state=False,
):
    """Build a Config-shaped stand-in exposing only the four attributes used."""
    return SimpleNamespace(
        filter_inventory=filter_inventory,
        reconciler_mode=reconciler_mode,
        ignore_provision_state=ignore_provision_state,
        ignore_maintenance_state=ignore_maintenance_state,
    )


class TestNormalizeFilters:
    def test_dict_input_is_wrapped_in_list(self):
        f = {"status": "active", "tag": "managed-by-osism"}
        df = DeviceFilter(_config(filter_inventory=f))
        assert df.normalize_filters() == [f]

    def test_list_input_is_returned_unchanged(self):
        f = [{"site": "dc1"}, {"site": "dc2"}]
        df = DeviceFilter(_config(filter_inventory=f))
        assert df.normalize_filters() == f

    def test_empty_list_is_returned_as_is(self):
        df = DeviceFilter(_config(filter_inventory=[]))
        assert df.normalize_filters() == []

    def test_mutating_returned_list_for_dict_input_does_not_mutate_config(self):
        # Dict input is wrapped in a *fresh* one-element list, so appending to
        # the result must not be observable on ``config.filter_inventory``.
        original = {"status": "active"}
        df = DeviceFilter(_config(filter_inventory=original))
        result = df.normalize_filters()
        result.append({"extra": "filter"})
        # ``filter_inventory`` is still the original dict (and unchanged).
        assert df.config.filter_inventory == {"status": "active"}
        assert df.config.filter_inventory is original


class TestApplyMetalboxFilterModifications:
    def test_string_ironic_tag_is_removed_and_role_added(self):
        df = DeviceFilter(_config())
        result = df._apply_metalbox_filter_modifications(
            [{"tag": "managed-by-ironic", "status": "active"}]
        )
        assert result == [{"status": "active", "role": "metalbox"}]

    def test_other_string_tag_is_preserved_and_role_added(self):
        df = DeviceFilter(_config())
        result = df._apply_metalbox_filter_modifications(
            [{"tag": "production", "status": "active"}]
        )
        assert result == [{"tag": "production", "status": "active", "role": "metalbox"}]

    def test_list_with_ironic_and_others_strips_ironic_only(self):
        df = DeviceFilter(_config())
        result = df._apply_metalbox_filter_modifications(
            [{"tag": ["managed-by-ironic", "production", "edge"]}]
        )
        assert result == [{"tag": ["production", "edge"], "role": "metalbox"}]

    def test_list_containing_only_ironic_removes_tag_entirely(self):
        df = DeviceFilter(_config())
        result = df._apply_metalbox_filter_modifications(
            [{"tag": ["managed-by-ironic"], "status": "active"}]
        )
        assert result == [{"status": "active", "role": "metalbox"}]

    def test_list_without_ironic_passes_through_unchanged(self):
        df = DeviceFilter(_config())
        result = df._apply_metalbox_filter_modifications(
            [{"tag": ["production", "edge"]}]
        )
        assert result == [{"tag": ["production", "edge"], "role": "metalbox"}]

    def test_missing_tag_key_only_adds_role(self):
        df = DeviceFilter(_config())
        result = df._apply_metalbox_filter_modifications([{"status": "active"}])
        assert result == [{"status": "active", "role": "metalbox"}]

    def test_multiple_input_filters_transformed_independently_in_order(self):
        df = DeviceFilter(_config())
        result = df._apply_metalbox_filter_modifications(
            [
                {"tag": "managed-by-ironic", "site": "dc1"},
                {"tag": ["managed-by-ironic", "production"], "site": "dc2"},
                {"site": "dc3"},
            ]
        )
        assert result == [
            {"site": "dc1", "role": "metalbox"},
            {"tag": ["production"], "site": "dc2", "role": "metalbox"},
            {"site": "dc3", "role": "metalbox"},
        ]

    def test_input_filter_dicts_are_not_mutated(self):
        df = DeviceFilter(_config())
        original_a = {"tag": "managed-by-ironic", "site": "dc1"}
        original_b = {"tag": ["managed-by-ironic", "production"], "site": "dc2"}
        # Snapshot for comparison.
        snapshot_a = {"tag": "managed-by-ironic", "site": "dc1"}
        snapshot_b = {"tag": ["managed-by-ironic", "production"], "site": "dc2"}
        df._apply_metalbox_filter_modifications([original_a, original_b])
        assert original_a == snapshot_a
        assert original_b == snapshot_b


class TestApplySwitchFilterModifications:
    def test_string_ironic_tag_is_rewritten_to_metalbox(self):
        df = DeviceFilter(_config())
        result = df._apply_switch_filter_modifications(
            [{"tag": "managed-by-ironic", "status": "active"}], ["leaf"]
        )
        assert result == [
            {"tag": "managed-by-metalbox", "status": "active", "role": "leaf"}
        ]

    def test_list_with_ironic_rewrites_in_place_and_preserves_order(self):
        df = DeviceFilter(_config())
        result = df._apply_switch_filter_modifications(
            [{"tag": ["alpha", "managed-by-ironic", "beta"]}], ["leaf"]
        )
        assert result == [
            {"tag": ["alpha", "managed-by-metalbox", "beta"], "role": "leaf"}
        ]

    def test_other_string_tag_is_left_untouched(self):
        df = DeviceFilter(_config())
        result = df._apply_switch_filter_modifications(
            [{"tag": "production"}], ["leaf"]
        )
        assert result == [{"tag": "production", "role": "leaf"}]

    def test_missing_tag_adds_managed_by_metalbox(self):
        df = DeviceFilter(_config())
        result = df._apply_switch_filter_modifications([{"status": "active"}], ["leaf"])
        assert result == [
            {"status": "active", "tag": "managed-by-metalbox", "role": "leaf"}
        ]

    def test_multiple_switch_roles_expand_one_filter_per_role(self):
        df = DeviceFilter(_config())
        result = df._apply_switch_filter_modifications(
            [{"site": "dc1"}], ["leaf", "spine"]
        )
        assert result == [
            {"site": "dc1", "tag": "managed-by-metalbox", "role": "leaf"},
            {"site": "dc1", "tag": "managed-by-metalbox", "role": "spine"},
        ]

    def test_empty_switch_roles_yields_no_filters(self):
        df = DeviceFilter(_config())
        assert df._apply_switch_filter_modifications([{"site": "dc1"}], []) == []

    def test_two_filters_times_two_roles_is_filter_major(self):
        df = DeviceFilter(_config())
        result = df._apply_switch_filter_modifications(
            [{"site": "dc1"}, {"site": "dc2"}], ["leaf", "spine"]
        )
        assert result == [
            {"site": "dc1", "tag": "managed-by-metalbox", "role": "leaf"},
            {"site": "dc1", "tag": "managed-by-metalbox", "role": "spine"},
            {"site": "dc2", "tag": "managed-by-metalbox", "role": "leaf"},
            {"site": "dc2", "tag": "managed-by-metalbox", "role": "spine"},
        ]

    def test_originals_are_not_mutated(self):
        df = DeviceFilter(_config())
        original = {"tag": ["managed-by-ironic", "production"], "site": "dc1"}
        snapshot = {"tag": ["managed-by-ironic", "production"], "site": "dc1"}
        df._apply_switch_filter_modifications([original], ["leaf", "spine"])
        assert original == snapshot


class TestBuildIronicFilter:
    def test_missing_tag_adds_ironic_as_list(self):
        df = DeviceFilter(_config())
        result = df.build_ironic_filter({"status": "active"})
        assert result == {
            "status": "active",
            "tag": ["managed-by-ironic"],
            "cf_provision_state": ["active"],
        }

    def test_string_tag_is_promoted_to_list_with_ironic_appended(self):
        df = DeviceFilter(_config())
        result = df.build_ironic_filter({"tag": "managed-by-osism"})
        assert result["tag"] == ["managed-by-osism", "managed-by-ironic"]

    def test_list_tag_without_ironic_gets_ironic_appended(self):
        df = DeviceFilter(_config())
        result = df.build_ironic_filter({"tag": ["managed-by-osism", "production"]})
        assert result["tag"] == [
            "managed-by-osism",
            "production",
            "managed-by-ironic",
        ]

    def test_list_tag_already_containing_ironic_is_unchanged(self):
        df = DeviceFilter(_config())
        result = df.build_ironic_filter(
            {"tag": ["managed-by-ironic", "managed-by-osism"]}
        )
        # Ironic is already present; no duplicate appended.
        assert result["tag"] == ["managed-by-ironic", "managed-by-osism"]

    def test_provision_state_added_when_manager_mode_and_not_ignored(self):
        df = DeviceFilter(
            _config(reconciler_mode="manager", ignore_provision_state=False)
        )
        result = df.build_ironic_filter({"status": "active"})
        assert result["cf_provision_state"] == ["active"]

    def test_provision_state_skipped_in_metalbox_mode(self):
        df = DeviceFilter(
            _config(reconciler_mode="metalbox", ignore_provision_state=False)
        )
        result = df.build_ironic_filter({"status": "active"})
        assert "cf_provision_state" not in result

    def test_provision_state_skipped_when_ignore_flag_set(self):
        df = DeviceFilter(
            _config(reconciler_mode="manager", ignore_provision_state=True)
        )
        result = df.build_ironic_filter({"status": "active"})
        assert "cf_provision_state" not in result

    def test_original_base_filter_is_not_mutated(self):
        df = DeviceFilter(_config())
        original = {"tag": ["managed-by-osism"], "status": "active"}
        snapshot = {"tag": ["managed-by-osism"], "status": "active"}
        df.build_ironic_filter(original)
        assert original == snapshot


class TestFilterByMaintenance:
    def test_ignore_flag_returns_devices_unchanged(self):
        df = DeviceFilter(_config(ignore_maintenance_state=True))
        devices = [
            make_device(1, "d1", custom_fields={"maintenance": True}),
            make_device(2, "d2", custom_fields={"maintenance": False}),
        ]
        assert df.filter_by_maintenance(devices) == devices

    def test_true_devices_filtered_out_others_kept(self):
        df = DeviceFilter(_config(ignore_maintenance_state=False))
        d_true = make_device(1, "d1", custom_fields={"maintenance": True})
        d_false = make_device(2, "d2", custom_fields={"maintenance": False})
        d_missing = make_device(3, "d3", custom_fields={})
        d_none = make_device(4, "d4", custom_fields={"maintenance": None})
        result = df.filter_by_maintenance([d_true, d_false, d_missing, d_none])
        assert result == [d_false, d_missing, d_none]

    def test_truthy_but_not_true_value_is_kept(self):
        # The check is ``is not True`` (identity), not ``not <truthy>``: a
        # ``maintenance=1`` device must still pass through.
        df = DeviceFilter(_config(ignore_maintenance_state=False))
        d = make_device(1, "d1", custom_fields={"maintenance": 1})
        assert df.filter_by_maintenance([d]) == [d]

    def test_all_in_maintenance_returns_empty(self):
        df = DeviceFilter(_config(ignore_maintenance_state=False))
        devices = [
            make_device(1, "d1", custom_fields={"maintenance": True}),
            make_device(2, "d2", custom_fields={"maintenance": True}),
        ]
        assert df.filter_by_maintenance(devices) == []

    def test_empty_input_returns_empty(self):
        df = DeviceFilter(_config(ignore_maintenance_state=False))
        assert df.filter_by_maintenance([]) == []


class TestFilterNonIronicDevices:
    def test_ironic_tagged_devices_are_removed(self):
        df = DeviceFilter(_config(ignore_maintenance_state=True))
        ironic = make_device(1, "d1", tags=("managed-by-ironic",))
        plain = make_device(2, "d2", tags=("managed-by-osism",))
        result = df.filter_non_ironic_devices([ironic, plain])
        assert result == [plain]

    def test_with_ignore_maintenance_maintenance_check_is_skipped(self):
        df = DeviceFilter(_config(ignore_maintenance_state=True))
        in_maint = make_device(
            1, "d1", tags=("managed-by-osism",), custom_fields={"maintenance": True}
        )
        result = df.filter_non_ironic_devices([in_maint])
        assert result == [in_maint]

    def test_without_ignore_maintenance_both_filters_applied(self):
        df = DeviceFilter(_config(ignore_maintenance_state=False))
        # Non-ironic but in maintenance => removed.
        in_maint = make_device(
            1, "d1", tags=("managed-by-osism",), custom_fields={"maintenance": True}
        )
        # Non-ironic, not in maintenance => kept.
        ok = make_device(
            2, "d2", tags=("managed-by-osism",), custom_fields={"maintenance": False}
        )
        # Ironic => removed before maintenance check.
        ironic = make_device(
            3, "d3", tags=("managed-by-ironic",), custom_fields={"maintenance": False}
        )
        result = df.filter_non_ironic_devices([in_maint, ok, ironic])
        assert result == [ok]

    def test_multiple_tags_including_ironic_filters_out(self):
        df = DeviceFilter(_config(ignore_maintenance_state=True))
        d = make_device(1, "d1", tags=("managed-by-osism", "managed-by-ironic"))
        assert df.filter_non_ironic_devices([d]) == []

    def test_empty_input_returns_empty(self):
        df = DeviceFilter(_config(ignore_maintenance_state=False))
        assert df.filter_non_ironic_devices([]) == []


class TestDeduplicateDevices:
    def test_duplicate_ids_keep_last_occurrence(self):
        df = DeviceFilter(_config())
        first = make_device(1, "first")
        second = make_device(1, "second")
        result = df.deduplicate_devices([first, second])
        # ``unique_devices = {dev.id: dev for dev in devices}`` -- the second
        # write at the same key wins per dict-insertion semantics.
        assert result == [second]

    def test_unique_ids_preserve_insertion_order(self):
        df = DeviceFilter(_config())
        a = make_device(1, "a")
        b = make_device(2, "b")
        c = make_device(3, "c")
        assert df.deduplicate_devices([a, b, c]) == [a, b, c]

    def test_empty_input_returns_empty(self):
        df = DeviceFilter(_config())
        assert df.deduplicate_devices([]) == []

    def test_single_device_round_trips(self):
        df = DeviceFilter(_config())
        d = make_device(1, "d1")
        assert df.deduplicate_devices([d]) == [d]


class TestBuildDnsmasqFilters:
    def test_single_dict_input_with_tag_strips_tag(self):
        df = DeviceFilter(
            _config(filter_inventory={"status": "active", "tag": "managed-by-osism"})
        )
        assert df.build_dnsmasq_filters() == [{"status": "active"}]

    def test_list_input_strips_tag_from_each_dict(self):
        df = DeviceFilter(
            _config(
                filter_inventory=[
                    {"site": "dc1", "tag": "managed-by-osism"},
                    {"site": "dc2", "tag": ["managed-by-osism", "production"]},
                ]
            )
        )
        assert df.build_dnsmasq_filters() == [
            {"site": "dc1"},
            {"site": "dc2"},
        ]

    def test_input_without_tag_passes_through(self):
        df = DeviceFilter(_config(filter_inventory={"status": "active"}))
        assert df.build_dnsmasq_filters() == [{"status": "active"}]

    def test_originals_are_not_mutated(self):
        original = {"status": "active", "tag": "managed-by-osism"}
        snapshot = {"status": "active", "tag": "managed-by-osism"}
        df = DeviceFilter(_config(filter_inventory=original))
        df.build_dnsmasq_filters()
        assert original == snapshot


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
