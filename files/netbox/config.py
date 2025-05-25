# SPDX-License-Identifier: Apache-2.0

"""Configuration management for NetBox integration."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Union

from dynaconf import Dynaconf

# Default configuration values
DEFAULT_INVENTORY_PATH = "/inventory.pre"
DEFAULT_TEMPLATE_PATH = "/netbox/templates/"
DEFAULT_DATA_TYPES = ["primary_ip", "config_context", "netplan_parameters"]
DEFAULT_IGNORED_ROLES = ["housing", "pdu", "other", "oob"]
DEFAULT_FILTER_INVENTORY = {"status": "active", "tag": "managed-by-osism"}
DEFAULT_RETRY_ATTEMPTS = 10
DEFAULT_RETRY_DELAY = 1
DEFAULT_MTU = 9100
DEFAULT_LOCAL_AS_PREFIX = 42
DEFAULT_FRR_SWITCH_ROLES = [
    "leaf",
    "accessleaf",
    "dataleaf",
    "storageleaf",
    "borderleaf",
    "serviceleaf",
]
DEFAULT_RECONCILER_MODE = "manager"
ALLOWED_RECONCILER_MODES = ["manager", "metalbox"]

# Initialize settings once at module level
SETTINGS = Dynaconf(
    envvar_prefix=False,  # No prefix, use exact environment variable names
    environments=False,  # Disable environments feature
    load_dotenv=False,  # Don't load .env files
)


@dataclass
class Config:
    """Configuration settings for NetBox integration.

    Attributes:
        netbox_url: NetBox API URL
        netbox_token: Authentication token for NetBox API
        ignore_ssl_errors: Whether to ignore SSL certificate errors
        retry_attempts: Number of retry attempts for API calls
        retry_delay: Delay in seconds between retry attempts
        inventory_path: Path where inventory files will be written
        template_path: Path to Jinja2 templates
        data_types: List of data types to extract from devices
        ignored_roles: Device roles to exclude from inventory
        filter_inventory: Filter(s) for device selection from NetBox
        default_local_as_prefix: Default local AS prefix for FRR configuration
        frr_switch_roles: Device roles considered as switches for FRR uplinks
        reconciler_mode: Operating mode for the reconciler (manager or metalbox)
    """

    netbox_url: str
    netbox_token: str
    ignore_ssl_errors: bool = True
    retry_attempts: int = DEFAULT_RETRY_ATTEMPTS
    retry_delay: int = DEFAULT_RETRY_DELAY
    inventory_path: Path = field(default_factory=lambda: Path(DEFAULT_INVENTORY_PATH))
    template_path: Path = field(default_factory=lambda: Path(DEFAULT_TEMPLATE_PATH))
    data_types: List[str] = field(default_factory=lambda: DEFAULT_DATA_TYPES.copy())
    ignored_roles: List[str] = field(
        default_factory=lambda: DEFAULT_IGNORED_ROLES.copy()
    )
    filter_inventory: Union[Dict[str, Any], List[Dict[str, Any]]] = field(
        default_factory=lambda: DEFAULT_FILTER_INVENTORY.copy()
    )
    default_mtu: int = DEFAULT_MTU
    default_local_as_prefix: int = DEFAULT_LOCAL_AS_PREFIX
    frr_switch_roles: List[str] = field(
        default_factory=lambda: DEFAULT_FRR_SWITCH_ROLES.copy()
    )
    reconciler_mode: str = DEFAULT_RECONCILER_MODE

    @classmethod
    def from_environment(cls) -> "Config":
        """Create configuration from environment variables using dynaconf.

        Returns:
            Config: Configuration instance populated from environment variables

        Raises:
            ValueError: If required environment variables are missing
        """
        # Required settings
        netbox_url = SETTINGS.get("NETBOX_API")
        if not netbox_url:
            raise ValueError("NETBOX_API environment variable is required")

        netbox_token = SETTINGS.get("NETBOX_TOKEN", cls._read_secret("NETBOX_TOKEN"))
        if not netbox_token:
            raise ValueError("NETBOX_TOKEN not found in environment or secrets")

        # Optional settings with defaults
        data_types = SETTINGS.get("NETBOX_DATA_TYPES", DEFAULT_DATA_TYPES)

        ignored_roles = SETTINGS.get("NETBOX_IGNORED_ROLES", DEFAULT_IGNORED_ROLES)
        ignored_roles = [
            role.lower() for role in ignored_roles
        ]  # Normalize to lowercase

        filter_inventory = SETTINGS.get(
            "NETBOX_FILTER_INVENTORY", DEFAULT_FILTER_INVENTORY
        )

        # Get reconciler mode and validate it
        reconciler_mode = SETTINGS.get(
            "INVENTORY_RECONCILER_MODE", DEFAULT_RECONCILER_MODE
        )
        if reconciler_mode not in ALLOWED_RECONCILER_MODES:
            raise ValueError(
                f"INVENTORY_RECONCILER_MODE must be one of {ALLOWED_RECONCILER_MODES}, "
                f"got '{reconciler_mode}'"
            )

        return cls(
            netbox_url=netbox_url,
            netbox_token=netbox_token,
            ignore_ssl_errors=SETTINGS.get("IGNORE_SSL_ERRORS", True),
            inventory_path=Path(SETTINGS.get("INVENTORY_PATH", DEFAULT_INVENTORY_PATH)),
            template_path=Path(SETTINGS.get("TEMPLATE_PATH", DEFAULT_TEMPLATE_PATH)),
            data_types=data_types,
            ignored_roles=ignored_roles,
            filter_inventory=filter_inventory,
            default_mtu=SETTINGS.get("DEFAULT_MTU", DEFAULT_MTU),
            default_local_as_prefix=SETTINGS.get(
                "DEFAULT_LOCAL_AS_PREFIX", DEFAULT_LOCAL_AS_PREFIX
            ),
            frr_switch_roles=SETTINGS.get("FRR_SWITCH_ROLES", DEFAULT_FRR_SWITCH_ROLES),
            reconciler_mode=reconciler_mode,
        )

    @staticmethod
    def _read_secret(secret_name: str) -> str:
        """Read secret from file system.

        Args:
            secret_name: Name of the secret to read

        Returns:
            str: Secret value or empty string if not found
        """
        secret_path = Path(f"/run/secrets/{secret_name}")
        try:
            return secret_path.read_text(encoding="utf-8").strip()
        except (EnvironmentError, FileNotFoundError):
            return ""
