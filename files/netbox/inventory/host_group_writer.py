# SPDX-License-Identifier: Apache-2.0

"""Host group writing functionality for inventory management."""

from typing import Any, Dict, List

import jinja2
from loguru import logger

from config import Config
from .base import BaseInventoryComponent


class HostGroupWriter(BaseInventoryComponent):
    """Handles writing host groups to inventory files."""

    def __init__(self, config: Config):
        super().__init__(config)
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(searchpath=str(config.template_path))
        )

    def write_host_groups(self, devices_to_roles: Dict[str, List[Any]]) -> None:
        """Write host groups to inventory file based on device roles.

        Args:
            devices_to_roles: Dictionary mapping role slugs to lists of devices
        """
        template = self.jinja_env.get_template("netbox.hosts.j2")
        result = template.render({"devices_to_roles": devices_to_roles})

        output_file = self.config.inventory_path / "20-netbox"
        logger.debug(f"Writing host groups from NetBox to {output_file}")

        with open(output_file, "w+", encoding="utf-8") as fp:
            # Remove empty lines
            cleaned_lines = [line for line in result.splitlines() if line]
            fp.write("\n".join(cleaned_lines))
