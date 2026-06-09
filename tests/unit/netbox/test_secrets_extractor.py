# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/extractors/secrets_extractor.py.

The extractor reads the ``secrets`` custom field (a dict of Ansible Vault
values) and drops keys starting with ``remote_board_`` or ``ironic_osism_``.
It only filters keys -- values (including ``$ANSIBLE_VAULT;`` strings) are
returned untouched; the ``!vault`` serialization happens later (tier 7).
"""

import pytest

from extractors.secrets_extractor import SecretsExtractor

from .conftest import make_device


def _device(secrets):
    return make_device(1, "node1", custom_fields={"secrets": secrets})


class TestExtract:
    def test_remote_board_keys_filtered_out(self):
        secrets = {
            "bmc_password": "x",
            "remote_board_username": "u",
            "remote_board_password": "p",
        }
        assert SecretsExtractor().extract(_device(secrets)) == {"bmc_password": "x"}

    def test_ironic_osism_keys_filtered_out(self):
        secrets = {"keep": "v", "ironic_osism_password": "p"}
        assert SecretsExtractor().extract(_device(secrets)) == {"keep": "v"}

    def test_substring_match_is_kept(self):
        # 'x_remote_board_y' contains but does not *start with* a reserved
        # prefix, so startswith() keeps it.
        secrets = {"x_remote_board_y": "v"}
        assert SecretsExtractor().extract(_device(secrets)) == {"x_remote_board_y": "v"}

    def test_only_reserved_keys_returns_none(self):
        secrets = {"remote_board_username": "u", "ironic_osism_token": "t"}
        assert SecretsExtractor().extract(_device(secrets)) is None

    def test_none_custom_fields_returns_none(self):
        device = make_device(1, "node1", custom_fields=None)
        assert SecretsExtractor().extract(device) is None

    def test_missing_secrets_field_returns_none(self):
        device = make_device(1, "node1", custom_fields={"other": 1})
        assert SecretsExtractor().extract(device) is None

    @pytest.mark.parametrize("secrets", [None, "", 0])
    def test_falsy_secrets_returns_none(self, secrets):
        assert SecretsExtractor().extract(_device(secrets)) is None

    @pytest.mark.parametrize("secrets", [["a", "b"], "a string"])
    def test_non_dict_secrets_returns_none(self, secrets):
        assert SecretsExtractor().extract(_device(secrets)) is None

    def test_vault_values_passed_through_untouched(self):
        vault = "$ANSIBLE_VAULT;1.1;AES256\n3365343656663230\n"
        secrets = {"frr_bmc_password": vault, "remote_board_password": vault}
        result = SecretsExtractor().extract(_device(secrets))
        # The reserved key is dropped; the kept value is byte-for-byte unchanged.
        assert result == {"frr_bmc_password": vault}
        assert result["frr_bmc_password"] == vault

    def test_extra_kwargs_are_ignored(self):
        assert SecretsExtractor().extract(_device({"keep": "v"}), unused="x") == {
            "keep": "v"
        }


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
