# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/config.py.

The module-level ``SETTINGS`` (a dynaconf instance) is replaced with a
``FakeSettings`` dict wrapper for every test so the suite never depends on,
or leaks into, real environment variables.
"""

from pathlib import Path

import pytest

import config
from config import Config

from .conftest import FakeSettings


@pytest.fixture(autouse=True)
def isolate_settings(monkeypatch):
    """Install an empty FakeSettings on ``config.SETTINGS`` for every test.

    monkeypatch restores the real dynaconf instance afterwards, so no SETTINGS
    state leaks between tests. Tests that need specific values call the
    ``set_settings`` helper.
    """
    monkeypatch.setattr(config, "SETTINGS", FakeSettings({}))


@pytest.fixture
def set_settings(monkeypatch):
    """Return a helper that installs a FakeSettings with the given values."""

    def _install(values):
        monkeypatch.setattr(config, "SETTINGS", FakeSettings(values))

    return _install


class TestDefaultConstants:
    def test_frr_switch_roles(self):
        assert config.DEFAULT_FRR_SWITCH_ROLES == [
            "leaf",
            "accessleaf",
            "dataleaf",
            "storageleaf",
            "borderleaf",
            "serviceleaf",
            "servicesleaf",
            "transferleaf",
            "computeleaf",
        ]

    def test_dnsmasq_switch_roles(self):
        # spine + superspine + every FRR role except servicesleaf -- the
        # asymmetry is intentional; this guards against accidental drift.
        assert config.DEFAULT_DNSMASQ_SWITCH_ROLES == [
            "spine",
            "superspine",
            "leaf",
            "accessleaf",
            "dataleaf",
            "storageleaf",
            "borderleaf",
            "serviceleaf",
            "transferleaf",
            "computeleaf",
        ]

    def test_dnsmasq_roles_differ_from_frr_only_by_documented_asymmetry(self):
        # The only FRR role absent from the dnsmasq set is servicesleaf; the
        # only extra dnsmasq roles are spine and superspine.
        frr = set(config.DEFAULT_FRR_SWITCH_ROLES)
        dnsmasq = set(config.DEFAULT_DNSMASQ_SWITCH_ROLES)
        assert frr - dnsmasq == {"servicesleaf"}
        assert dnsmasq - frr == {"spine", "superspine"}

    def test_allowed_reconciler_modes(self):
        assert config.ALLOWED_RECONCILER_MODES == [
            "manager",
            "manager-readonly",
            "metalbox",
        ]

    def test_default_data_types(self):
        assert config.DEFAULT_DATA_TYPES == [
            "primary_ip",
            "config_context",
            "netplan_parameters",
            "secrets",
        ]

    def test_default_ignored_roles(self):
        assert config.DEFAULT_IGNORED_ROLES == ["housing", "pdu", "other", "oob"]

    def test_default_filter_inventory(self):
        assert config.DEFAULT_FILTER_INVENTORY == {
            "status": "active",
            "tag": "managed-by-osism",
        }


class TestReadSecret:
    def test_existing_file_returns_stripped_content(self, tmp_path, monkeypatch):
        secret_file = tmp_path / "NETBOX_TOKEN"
        secret_file.write_text("abc\n", encoding="utf-8")
        monkeypatch.setattr(config, "Path", lambda _: secret_file)

        assert Config._read_secret("NETBOX_TOKEN") == "abc"

    def test_missing_file_returns_empty_string(self, tmp_path, monkeypatch):
        missing = tmp_path / "absent"
        monkeypatch.setattr(config, "Path", lambda _: missing)

        assert Config._read_secret("NETBOX_TOKEN") == ""

    def test_empty_file_returns_empty_string(self, tmp_path, monkeypatch):
        secret_file = tmp_path / "NETBOX_TOKEN"
        secret_file.write_text("", encoding="utf-8")
        monkeypatch.setattr(config, "Path", lambda _: secret_file)

        assert Config._read_secret("NETBOX_TOKEN") == ""


class TestFromEnvironment:
    @pytest.fixture(autouse=True)
    def stub_read_secret(self, monkeypatch):
        """Default the secrets file to empty so tests never read /run/secrets.

        Tests that exercise the secret fallback re-patch ``_read_secret`` with
        their own return value.
        """
        monkeypatch.setattr(Config, "_read_secret", staticmethod(lambda name: ""))

    def test_missing_netbox_api_raises(self, set_settings):
        set_settings({})
        with pytest.raises(
            ValueError, match="NETBOX_API environment variable is required"
        ):
            Config.from_environment()

    def test_missing_netbox_token_raises(self, set_settings):
        set_settings({"NETBOX_API": "http://netbox"})
        with pytest.raises(
            ValueError, match="NETBOX_TOKEN not found in environment or secrets"
        ):
            Config.from_environment()

    def test_token_falls_back_to_secret_file(self, set_settings, monkeypatch):
        set_settings({"NETBOX_API": "http://netbox"})
        monkeypatch.setattr(
            Config,
            "_read_secret",
            staticmethod(lambda name: "secret-from-file"),
        )
        cfg = Config.from_environment()
        assert cfg.netbox_token == "secret-from-file"

    def test_api_and_token_are_stripped(self, set_settings):
        set_settings({"NETBOX_API": "  http://netbox  ", "NETBOX_TOKEN": "  tok123  "})
        cfg = Config.from_environment()
        assert cfg.netbox_url == "http://netbox"
        assert cfg.netbox_token == "tok123"

    def test_defaults_applied(self, set_settings):
        set_settings({"NETBOX_API": "http://netbox", "NETBOX_TOKEN": "tok"})
        cfg = Config.from_environment()
        assert cfg.ignore_ssl_errors is True
        assert cfg.inventory_path == Path("/inventory.pre")
        assert cfg.template_path == Path("/netbox/templates/")
        assert cfg.data_types == config.DEFAULT_DATA_TYPES
        assert cfg.ignored_roles == config.DEFAULT_IGNORED_ROLES
        assert cfg.filter_inventory == config.DEFAULT_FILTER_INVENTORY
        assert cfg.frr_switch_roles == config.DEFAULT_FRR_SWITCH_ROLES
        assert cfg.dnsmasq_switch_roles == config.DEFAULT_DNSMASQ_SWITCH_ROLES
        assert cfg.default_mtu == 9100
        assert cfg.default_local_as_prefix == 4200
        assert cfg.dnsmasq_lease_time == "28d"
        assert cfg.reconciler_mode == "manager"
        assert cfg.inventory_from_netbox is True
        assert cfg.ignore_provision_state is False
        assert cfg.ignore_maintenance_state is False
        assert cfg.parallel_processing_enabled is True
        assert cfg.max_workers == 10
        assert cfg.max_retries == 3
        assert cfg.retry_delay == 1.0
        assert cfg.retry_backoff == 2.0
        assert cfg.api_timeout == 30

    def test_retry_attempts_is_fixed_default(self, set_settings):
        # retry_attempts is the connection-level retry knob consumed by
        # ConnectionManager.connect() and is intentionally not overridable
        # via the environment. The two retry controls are distinct:
        # `retry_attempts` governs the initial NetBox connection, while
        # `max_retries` / `retry_delay` / `retry_backoff` govern the
        # per-API-call retry decorator (see retry_utils.py).
        set_settings({"NETBOX_API": "http://netbox", "NETBOX_TOKEN": "tok"})
        cfg = Config.from_environment()
        assert cfg.retry_attempts == config.DEFAULT_RETRY_ATTEMPTS == 10

    def test_env_token_does_not_trigger_secret_file_read(
        self, set_settings, monkeypatch
    ):
        # Regression guard: ``from_environment`` previously evaluated
        # ``_read_secret("NETBOX_TOKEN")`` eagerly as the default argument to
        # ``SETTINGS.get(...)``, so the secrets file was read even when the
        # environment already supplied the token. The fallback must be lazy.
        set_settings({"NETBOX_API": "http://netbox", "NETBOX_TOKEN": "tok"})
        calls = []
        monkeypatch.setattr(
            Config,
            "_read_secret",
            staticmethod(lambda name: calls.append(name) or ""),
        )
        Config.from_environment()
        assert calls == []

    def test_returned_lists_are_isolated_from_module_defaults(self, set_settings):
        # Regression guard: ``from_environment`` previously returned the
        # module-level DEFAULT_* lists/dicts by reference, so mutating one
        # returned Config could leak into the shared defaults and into a
        # subsequent Config. The dataclass field factories use ``.copy()``
        # already, but ``from_environment`` is what produces the Config here,
        # so the isolation has to come from the classmethod.
        set_settings({"NETBOX_API": "http://netbox", "NETBOX_TOKEN": "tok"})
        cfg1 = Config.from_environment()

        cfg1.data_types.append("MUTATED")
        cfg1.filter_inventory["MUTATED"] = True
        cfg1.frr_switch_roles.append("MUTATED")
        cfg1.dnsmasq_switch_roles.append("MUTATED")

        # Module defaults are untouched.
        assert "MUTATED" not in config.DEFAULT_DATA_TYPES
        assert "MUTATED" not in config.DEFAULT_FILTER_INVENTORY
        assert "MUTATED" not in config.DEFAULT_FRR_SWITCH_ROLES
        assert "MUTATED" not in config.DEFAULT_DNSMASQ_SWITCH_ROLES

        # A second Config built from the same SETTINGS sees pristine defaults.
        cfg2 = Config.from_environment()
        assert cfg2.data_types == config.DEFAULT_DATA_TYPES
        assert cfg2.filter_inventory == config.DEFAULT_FILTER_INVENTORY
        assert cfg2.frr_switch_roles == config.DEFAULT_FRR_SWITCH_ROLES
        assert cfg2.dnsmasq_switch_roles == config.DEFAULT_DNSMASQ_SWITCH_ROLES

    @pytest.mark.parametrize("mode", ["manager", "manager-readonly", "metalbox"])
    def test_valid_reconciler_modes_accepted(self, set_settings, mode):
        set_settings(
            {
                "NETBOX_API": "http://netbox",
                "NETBOX_TOKEN": "tok",
                "INVENTORY_RECONCILER_MODE": mode,
            }
        )
        cfg = Config.from_environment()
        assert cfg.reconciler_mode == mode

    def test_invalid_reconciler_mode_rejected(self, set_settings):
        set_settings(
            {
                "NETBOX_API": "http://netbox",
                "NETBOX_TOKEN": "tok",
                "INVENTORY_RECONCILER_MODE": "foo",
            }
        )
        with pytest.raises(ValueError) as excinfo:
            Config.from_environment()
        # the error message must reference the allowed modes
        assert str(config.ALLOWED_RECONCILER_MODES) in str(excinfo.value)

    def test_reconciler_mode_whitespace_is_stripped(self, set_settings):
        set_settings(
            {
                "NETBOX_API": "http://netbox",
                "NETBOX_TOKEN": "tok",
                "INVENTORY_RECONCILER_MODE": "  metalbox  ",
            }
        )
        cfg = Config.from_environment()
        assert cfg.reconciler_mode == "metalbox"

    def test_ignored_roles_are_normalized_to_lowercase(self, set_settings):
        set_settings(
            {
                "NETBOX_API": "http://netbox",
                "NETBOX_TOKEN": "tok",
                "NETBOX_IGNORED_ROLES": ["Compute", "STORAGE"],
            }
        )
        cfg = Config.from_environment()
        assert cfg.ignored_roles == ["compute", "storage"]

    def test_filter_inventory_accepts_dict(self, set_settings):
        custom_filter = {"status": "active", "site": "dc1"}
        set_settings(
            {
                "NETBOX_API": "http://netbox",
                "NETBOX_TOKEN": "tok",
                "NETBOX_FILTER_INVENTORY": custom_filter,
            }
        )
        cfg = Config.from_environment()
        assert cfg.filter_inventory == custom_filter

    def test_filter_inventory_accepts_list_of_dicts(self, set_settings):
        custom_filter = [{"site": "dc1"}, {"site": "dc2"}]
        set_settings(
            {
                "NETBOX_API": "http://netbox",
                "NETBOX_TOKEN": "tok",
                "NETBOX_FILTER_INVENTORY": custom_filter,
            }
        )
        cfg = Config.from_environment()
        assert cfg.filter_inventory == custom_filter
