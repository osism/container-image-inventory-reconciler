# SPDX-License-Identifier: Apache-2.0

"""Group vars writing functionality for inventory management."""

from typing import Any, Dict

from loguru import logger
import yaml

from .base import BaseInventoryComponent


class GroupVarsWriter(BaseInventoryComponent):
    """Handles writing group_vars files for cluster and cluster group config contexts."""

    def write_cluster_group_vars(
        self, cluster_config_contexts: Dict[str, Dict[str, Any]]
    ) -> None:
        """Write group_vars files for clusters and cluster groups with config contexts.

        Args:
            cluster_config_contexts: Dictionary mapping group names to config contexts
        """
        if not cluster_config_contexts:
            logger.debug("No cluster config contexts to write")
            return

        group_vars_path = self.config.inventory_path / "group_vars"
        group_vars_path.mkdir(parents=True, exist_ok=True)

        for group_name, config_context in cluster_config_contexts.items():
            if not config_context:
                continue

            # Create group_vars file with the same name as the inventory group
            group_vars_file = group_vars_path / f"{group_name}.yml"

            logger.debug(f"Writing group_vars for {group_name} to {group_vars_file}")

            with open(group_vars_file, "w", encoding="utf-8") as fp:
                yaml.dump(
                    config_context, fp, default_flow_style=False, Dumper=yaml.Dumper
                )

        logger.info(
            f"Created {len(cluster_config_contexts)} group_vars files for cluster config contexts"
        )
