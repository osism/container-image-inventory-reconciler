# SPDX-License-Identifier: Apache-2.0

"""Configuration management for NetBox integration."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Union

from dynaconf import Dynaconf

# Default configuration values
DEFAULT_INVENTORY_PATH = "/inventory.pre"
DEFAULT_TEMPLATE_PATH = "/netbox/templates/"
DEFAULT_DATA_TYPES = ["primary_ip", "config_context", "netplan_parameters", "secrets"]
DEFAULT_IGNORED_ROLES = ["housing", "pdu", "other", "oob"]
DEFAULT_FILTER_INVENTORY = {"status": "active", "tag": "managed-by-osism"}
DEFAULT_RETRY_ATTEMPTS = 10
DEFAULT_RETRY_DELAY = 1
DEFAULT_MTU = 9100
DEFAULT_LOCAL_AS_PREFIX = 4200
DEFAULT_METALBOX_IPV6 = "fd33:fd0e:2aee::42/128"
DEFAULT_FRR_SWITCH_ROLES = [
    "leaf",
    "accessleaf",
    "dataleaf",
    "storageleaf",
    "borderleaf",
    "serviceleaf",
    "transferleaf",
    "computeleaf",
]
DEFAULT_DNSMASQ_SWITCH_ROLES = [
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
DEFAULT_DNSMASQ_LEASE_TIME = "28d"
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
        dnsmasq_switch_roles: Device roles considered as switches for dnsmasq operations
        dnsmasq_lease_time: DHCP lease time for dnsmasq DHCP ranges (e.g. "28d", "12h", "infinite")
        reconciler_mode: Operating mode for the reconciler (manager or metalbox)
        inventory_from_netbox: Whether to write inventory files to DEFAULT_INVENTORY_PATH
        ignore_provision_state: Ignore cf_provision_state filter for Ironic devices
        ignore_maintenance_state: Ignore maintenance state filter for devices
        parallel_processing_enabled: Enable parallel device processing for improved performance
        max_workers: Maximum number of parallel workers (1-50)
        max_retries: Maximum retry attempts for failed API calls (0-10)
        retry_delay: Initial delay between retries in seconds (0.1-60.0)
        retry_backoff: Exponential backoff multiplier for retries (1.0-10.0)
        api_timeout: API request timeout in seconds (5-300)
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
    dnsmasq_switch_roles: List[str] = field(
        default_factory=lambda: DEFAULT_DNSMASQ_SWITCH_ROLES.copy()
    )
    dnsmasq_lease_time: str = DEFAULT_DNSMASQ_LEASE_TIME
    reconciler_mode: str = DEFAULT_RECONCILER_MODE
    inventory_from_netbox: bool = True
    ignore_provision_state: bool = False
    ignore_maintenance_state: bool = False
    # Parallel processing settings
    parallel_processing_enabled: bool = True
    max_workers: int = 10
    max_retries: int = 3
    retry_delay: float = 1.0
    retry_backoff: float = 2.0
    api_timeout: int = 30

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
        # Ensure URL is always treated as a string and strip whitespace
        netbox_url = str(netbox_url).strip()

        netbox_token = SETTINGS.get("NETBOX_TOKEN", cls._read_secret("NETBOX_TOKEN"))
        if not netbox_token:
            raise ValueError("NETBOX_TOKEN not found in environment or secrets")
        # Ensure token is always treated as a string and strip whitespace
        netbox_token = str(netbox_token).strip()

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
        # Ensure reconciler mode is always treated as a string and strip whitespace
        reconciler_mode = str(reconciler_mode).strip()
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
            dnsmasq_switch_roles=SETTINGS.get(
                "DNSMASQ_SWITCH_ROLES", DEFAULT_DNSMASQ_SWITCH_ROLES
            ),
            dnsmasq_lease_time=SETTINGS.get(
                "DNSMASQ_LEASE_TIME", DEFAULT_DNSMASQ_LEASE_TIME
            ),
            reconciler_mode=reconciler_mode,
            inventory_from_netbox=SETTINGS.get("INVENTORY_FROM_NETBOX", True),
            ignore_provision_state=SETTINGS.get(
                "INVENTORY_IGNORE_PROVISION_STATE", False
            ),
            ignore_maintenance_state=SETTINGS.get(
                "INVENTORY_IGNORE_MAINTENANCE_STATE", False
            ),
            parallel_processing_enabled=SETTINGS.get(
                "PARALLEL_PROCESSING_ENABLED", True
            ),
            max_workers=SETTINGS.get("MAX_WORKERS", 10),
            max_retries=SETTINGS.get("MAX_RETRIES", 3),
            retry_delay=SETTINGS.get("RETRY_DELAY", 1.0),
            retry_backoff=SETTINGS.get("RETRY_BACKOFF", 2.0),
            api_timeout=SETTINGS.get("API_TIMEOUT", 30),
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
