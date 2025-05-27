# SPDX-License-Identifier: Apache-2.0

"""Base class for dnsmasq configuration management."""

from typing import Any

from loguru import logger
import yaml

from config import Config
from utils import get_inventory_hostname


class DnsmasqBase:
    """Base class for dnsmasq configuration handling."""

    def __init__(self, config: Config):
        self.config = config

    def write_dnsmasq_to_device(self, device: Any, dnsmasq_data: dict) -> None:
        """Write dnsmasq configuration data to device's host vars.

        Args:
            device: The NetBox device object
            dnsmasq_data: Dictionary containing dnsmasq configuration
        """
        # Determine base path for device files
        host_vars_path = self.config.inventory_path / "host_vars"
        # Use inventory_hostname if set, otherwise use device name
        hostname = get_inventory_hostname(device)
        device_pattern = f"{hostname}*"
        result = list(host_vars_path.glob(device_pattern))

        if len(result) > 1:
            logger.warning(
                f"Multiple matches found for {hostname}, skipping dnsmasq writing"
            )
            return

        base_path = result[0] if len(result) == 1 else None

        # Write to device-specific file
        if base_path:
            if base_path.is_dir():
                output_file = base_path / "999-netbox-dnsmasq.yml"
                logger.debug(f"Writing dnsmasq config for {hostname} to {output_file}")
                with open(output_file, "w+", encoding="utf-8") as fp:
                    yaml.dump(dnsmasq_data, fp, Dumper=yaml.Dumper)
            else:
                # For existing single file, append with separator
                logger.debug(f"Appending dnsmasq config for {hostname} to {base_path}")
                with open(base_path, "a", encoding="utf-8") as fp:
                    fp.write("\n# NetBox dnsmasq\n")
                    yaml.dump(dnsmasq_data, fp, Dumper=yaml.Dumper)
        else:
            # Create new directory structure
            device_dir = self.config.inventory_path / "host_vars" / hostname
            device_dir.mkdir(parents=True, exist_ok=True)
            output_file = device_dir / "999-netbox-dnsmasq.yml"
            logger.debug(f"Writing dnsmasq config for {hostname} to {output_file}")
            with open(output_file, "w+", encoding="utf-8") as fp:
                yaml.dump(dnsmasq_data, fp, Dumper=yaml.Dumper)
