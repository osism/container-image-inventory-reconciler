# SPDX-License-Identifier: Apache-2.0

"""Configuration management for NetBox integration."""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Any

from dynaconf import Dynaconf


# Initialize settings once at module level
SETTINGS = Dynaconf(
    envvar_prefix=False,  # No prefix, use exact environment variable names
    environments=False,  # Disable environments feature
    load_dotenv=False,  # Don't load .env files
)


@dataclass
class Config:
    """Configuration settings for NetBox integration."""

    netbox_url: str
    netbox_token: str
    ignore_ssl_errors: bool = True
    retry_attempts: int = 10
    retry_delay: int = 1
    inventory_path: Path = Path("/inventory.pre")
    template_path: Path = Path("/netbox/templates/")
    data_types: List[str] = None  # Configurable data types to extract
    ignored_roles: List[str] = None  # Device roles to ignore
    filter_inventory: Dict[str, Any] = None  # Custom filter for device selection

    @classmethod
    def from_environment(cls) -> "Config":
        """Create configuration from environment variables using dynaconf."""
        netbox_url = SETTINGS.get("NETBOX_API")
        if not netbox_url:
            raise ValueError("NETBOX_API environment variable is required")

        netbox_token = SETTINGS.get("NETBOX_TOKEN", cls._read_secret("NETBOX_TOKEN"))
        if not netbox_token:
            raise ValueError("NETBOX_TOKEN not found in environment or secrets")

        # Get data types from dynaconf (already a list)
        # Default: primary_ip and config_context
        data_types = SETTINGS.get("NETBOX_DATA_TYPES", ["primary_ip", "config_context"])

        # Get ignored roles from dynaconf (already a list)
        # Default: skip 'housing', 'pdu', 'other' and 'oob' roles
        ignored_roles = SETTINGS.get(
            "NETBOX_IGNORED_ROLES", ["housing", "pdu", "other", "oob"]
        )
        # Ensure lowercase for consistency
        ignored_roles = [role.lower() for role in ignored_roles]

        # Get filter inventory from dynaconf
        # Default: devices with state=active and tag=managed-by-osism
        filter_inventory = SETTINGS.get(
            "NETBOX_FILTER_INVENTORY", {"status": "active", "tag": "managed-by-osism"}
        )

        return cls(
            netbox_url=netbox_url,
            netbox_token=netbox_token,
            ignore_ssl_errors=SETTINGS.get("IGNORE_SSL_ERRORS", True),
            inventory_path=Path(SETTINGS.get("INVENTORY_PATH", "/inventory.pre")),
            template_path=Path(SETTINGS.get("TEMPLATE_PATH", "/netbox/templates/")),
            data_types=data_types,
            ignored_roles=ignored_roles,
            filter_inventory=filter_inventory,
        )

    @staticmethod
    def _read_secret(secret_name: str) -> str:
        """Read secret from file."""
        secret_path = Path(f"/run/secrets/{secret_name}")
        try:
            return secret_path.read_text(encoding="utf-8").strip()
        except (EnvironmentError, FileNotFoundError):
            return ""
