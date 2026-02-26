# SPDX-License-Identifier: Apache-2.0

"""Extractor for device secrets stored as Ansible Vault encrypted values."""

from typing import Any, Dict, Optional

from .base_extractor import BaseExtractor


class SecretsExtractor(BaseExtractor):
    """Extracts secrets from the 'secrets' custom field on NetBox devices."""

    def extract(self, device: Any, **kwargs) -> Optional[Dict[str, str]]:
        """Extract secrets custom field from device.

        The 'secrets' custom field is expected to contain a dictionary
        of key-value pairs where each value is an Ansible Vault encrypted
        string.

        Keys prefixed with ``remote_board_`` (e.g. ``remote_board_username``,
        ``remote_board_password``) or ``ironic_osism_`` are reserved for the
        Ironic integration and are excluded from the inventory host vars.

        Args:
            device: NetBox device object
            **kwargs: Additional parameters (unused)

        Returns:
            Dictionary of secret key-value pairs, or None if empty/not set
        """
        custom_fields = device.custom_fields or {}
        secrets = custom_fields.get("secrets")
        if not secrets or not isinstance(secrets, dict):
            return None

        filtered = {
            k: v
            for k, v in secrets.items()
            if not k.startswith(("remote_board_", "ironic_osism_"))
        }
        return filtered or None
