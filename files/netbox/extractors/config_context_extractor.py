# SPDX-License-Identifier: Apache-2.0

"""Config context extractor."""

from typing import Any, Dict

from .base_extractor import BaseExtractor


class ConfigContextExtractor(BaseExtractor):
    """Extracts config context from NetBox devices."""

    def extract(self, device: Any, **kwargs) -> Dict[str, Any]:
        """Extract config context from device.

        Filters out frr_parameters, netplan_parameters and ceph_parameters
        keys since those are handled by their dedicated extractors and
        written to separate files. This avoids duplication because NetBox
        merges local_context_data into config_context automatically.

        Also filters out first_boot: it holds values for the first-boot
        play that python-osism puts on a node's config drive, not host
        variables, and must not reach the inventory.

        Args:
            device: NetBox device object
            **kwargs: Additional parameters (unused)

        Returns:
            Config context dictionary without frr/netplan/ceph parameters
            and first_boot
        """
        ctx = device.config_context
        if isinstance(ctx, dict):
            ctx = {
                k: v
                for k, v in ctx.items()
                if k
                not in (
                    "frr_parameters",
                    "netplan_parameters",
                    "ceph_parameters",
                    "first_boot",
                )
                and k != ""
            }
        return ctx
