# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/device_mapping.py.

The module reads ``SETTINGS`` (re-exported by ``config``) eagerly via
``from config import SETTINGS``, so each test patches
``device_mapping.SETTINGS`` directly with a ``FakeSettings`` -- patching
``config.SETTINGS`` would leave the module-level binding stale.
"""

from types import SimpleNamespace

import pytest

import device_mapping
from device_mapping import build_device_role_mapping, build_device_tag_mapping

from .conftest import FakeSettings, make_device


@pytest.fixture(autouse=True)
def isolate_settings(monkeypatch):
    """Install an empty ``FakeSettings`` on the module under test.

    monkeypatch restores the original binding after each test so SETTINGS
    state never leaks between cases.
    """
    monkeypatch.setattr(device_mapping, "SETTINGS", FakeSettings({}))


@pytest.fixture
def set_settings(monkeypatch):
    """Return a helper that installs a ``FakeSettings`` with the given values."""

    def _install(values):
        monkeypatch.setattr(device_mapping, "SETTINGS", FakeSettings(values))

    return _install


def _role(slug):
    return SimpleNamespace(slug=slug)


def _site(slug):
    return SimpleNamespace(slug=slug)


# ---------------------------------------------------------------------------
# build_device_tag_mapping
# ---------------------------------------------------------------------------


class TestBuildDeviceTagMapping:
    def test_single_device_with_multiple_tags(self):
        d = make_device(1, "d1", tags=("foo", "bar"))
        result = build_device_tag_mapping([d])
        assert result == {"foo": [d], "bar": [d]}

    def test_only_excluded_tags_produces_empty_mapping(self):
        d = make_device(1, "d1", tags=("managed-by-osism", "managed-by-ironic"))
        assert build_device_tag_mapping([d]) == {}

    def test_excluded_and_non_excluded_tags_only_keep_non_excluded(self):
        d = make_device(
            1, "d1", tags=("managed-by-osism", "managed-by-ironic", "production")
        )
        result = build_device_tag_mapping([d])
        assert result == {"production": [d]}

    def test_two_devices_share_a_tag(self):
        d1 = make_device(1, "d1", tags=("production",))
        d2 = make_device(2, "d2", tags=("production",))
        result = build_device_tag_mapping([d1, d2])
        # Iteration-order preservation: d1 comes before d2.
        assert result == {"production": [d1, d2]}

    def test_empty_device_list_returns_empty_mapping(self):
        assert build_device_tag_mapping([]) == {}

    def test_device_with_no_tags_returns_empty_mapping(self):
        d = make_device(1, "d1", tags=())
        assert build_device_tag_mapping([d]) == {}


# ---------------------------------------------------------------------------
# build_device_role_mapping
# ---------------------------------------------------------------------------


class TestBuildDeviceRoleMapping:
    def test_device_without_managed_tag_is_skipped(self):
        d = make_device(1, "d1", role=_role("compute"), tags=())
        assert build_device_role_mapping([d]) == {}

    def test_ignored_role_skips_device(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {"compute": ["compute", "generic"]}})
        d = make_device(1, "d1", role=_role("compute"), tags=("managed-by-osism",))
        # The ``compute`` group is still pre-initialised as an empty list.
        result = build_device_role_mapping([d], ignored_roles=["compute"])
        assert result == {"compute": [], "generic": []}

    def test_ignored_roles_none_skips_nothing(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {}})
        d = make_device(1, "d1", role=_role("compute"), tags=("managed-by-osism",))
        # ignored_roles defaults to ``None`` -> no role is filtered out.
        result = build_device_role_mapping([d], ignored_roles=None)
        assert result == {"generic": ["d1"]}

    def test_ignored_roles_match_after_lowercasing(self, set_settings):
        # The device's role.slug is upper-cased; the production code lower-cases
        # it before checking the ignored list, so ``["compute"]`` matches.
        set_settings({"NETBOX_ROLE_MAPPING": {}})
        d = make_device(1, "d1", role=_role("Compute"), tags=("managed-by-osism",))
        result = build_device_role_mapping([d], ignored_roles=["compute"])
        assert result == {}

    def test_device_without_role_is_skipped(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {}})
        d = make_device(1, "d1", role=None, tags=("managed-by-osism",))
        assert build_device_role_mapping([d]) == {}

    def test_device_with_falsy_role_slug_is_skipped(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {}})
        d = make_device(1, "d1", role=_role(""), tags=("managed-by-osism",))
        assert build_device_role_mapping([d]) == {}

    def test_metalbox_role_is_assigned_to_fixed_groups(self, set_settings):
        # Even when NETBOX_ROLE_MAPPING contains a ``metalbox`` entry it is
        # ignored: metalbox devices always go to generic/manager/control.
        set_settings({"NETBOX_ROLE_MAPPING": {"metalbox": ["should-be-ignored"]}})
        d = make_device(1, "mb1", role=_role("metalbox"), tags=("managed-by-osism",))
        result = build_device_role_mapping([d])
        assert result["generic"] == ["mb1"]
        assert result["manager"] == ["mb1"]
        assert result["control"] == ["mb1"]
        assert "should-be-ignored" not in result["generic"]
        # The empty-group pre-init does still create the bogus group, but the
        # device must not have landed in it.
        assert result.get("should-be-ignored", []) == []

    def test_role_mapping_with_list_assigns_to_each_group(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {"compute": ["generic", "compute"]}})
        d = make_device(1, "c1", role=_role("compute"), tags=("managed-by-osism",))
        result = build_device_role_mapping([d])
        assert result["generic"] == ["c1"]
        assert result["compute"] == ["c1"]

    def test_role_mapping_with_non_list_value_warns_and_falls_back_to_generic(
        self, set_settings
    ):
        # A misconfigured mapping (string instead of list) emits a warning and
        # falls back to ``["generic"]``.
        set_settings({"NETBOX_ROLE_MAPPING": {"control": "manager"}})
        d = make_device(1, "c1", role=_role("control"), tags=("managed-by-osism",))
        result = build_device_role_mapping([d])
        assert result["generic"] == ["c1"]
        # The bogus mapping value is not interpreted as a list of group names.
        assert "manager" not in result or result["manager"] == []

    def test_unknown_role_defaults_to_generic(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {}})
        d = make_device(1, "d1", role=_role("worker"), tags=("managed-by-osism",))
        result = build_device_role_mapping([d])
        assert result == {"generic": ["d1"]}

    def test_site_grouping_creates_site_prefixed_group(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {}})
        d = make_device(
            1,
            "d1",
            role=_role("compute"),
            site=_site("muenchen"),
            tags=("managed-by-osism",),
        )
        result = build_device_role_mapping([d])
        assert result["site-muenchen"] == ["d1"]

    def test_no_site_means_no_site_group(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {}})
        d = make_device(
            1, "d1", role=_role("compute"), site=None, tags=("managed-by-osism",)
        )
        result = build_device_role_mapping([d])
        # No site group at all.
        assert not any(key.startswith("site-") for key in result)

    def test_falsy_site_slug_creates_no_site_group(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {}})
        d = make_device(
            1,
            "d1",
            role=_role("compute"),
            site=_site(""),
            tags=("managed-by-osism",),
        )
        result = build_device_role_mapping([d])
        assert not any(key.startswith("site-") for key in result)

    def test_duplicate_device_does_not_duplicate_hostname_in_groups(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {}})
        d = make_device(
            1,
            "d1",
            role=_role("compute"),
            site=_site("muenchen"),
            tags=("managed-by-osism",),
        )
        result = build_device_role_mapping([d, d])
        assert result["generic"] == ["d1"]
        assert result["site-muenchen"] == ["d1"]

    def test_empty_group_is_preserved_from_role_mapping(self, set_settings):
        # Even when no device matches ``unused``, the ``orphan`` group is still
        # pre-initialised to ``[]`` so downstream consumers can see it exists.
        set_settings({"NETBOX_ROLE_MAPPING": {"unused": ["orphan"]}})
        result = build_device_role_mapping([])
        assert result == {"orphan": []}

    def test_inventory_hostname_custom_field_overrides_device_name(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {}})
        d = make_device(
            1,
            "raw-name",
            role=_role("compute"),
            tags=("managed-by-osism",),
            custom_fields={"inventory_hostname": "pretty-name"},
        )
        result = build_device_role_mapping([d])
        assert result["generic"] == ["pretty-name"]

    def test_upper_case_role_slug_is_lowercased_before_lookup(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {"compute": ["generic", "compute"]}})
        d = make_device(1, "d1", role=_role("COMPUTE"), tags=("managed-by-osism",))
        result = build_device_role_mapping([d])
        assert result["compute"] == ["d1"]
        assert result["generic"] == ["d1"]

    def test_empty_devices_with_empty_mapping_returns_empty_dict(self, set_settings):
        set_settings({"NETBOX_ROLE_MAPPING": {}})
        assert build_device_role_mapping([]) == {}


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
