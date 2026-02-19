# SPDX-License-Identifier: Apache-2.0

"""Config context extractor."""

from typing import Any, Dict

from .base_extractor import BaseExtractor


class ConfigContextExtractor(BaseExtractor):
    """Extracts config context from NetBox devices."""

    def extract(self, device: Any, **kwargs) -> Dict[str, Any]:
        """Extract config context from device.

        Filters out frr_parameters and netplan_parameters keys since those
        are handled by their dedicated extractors and written to separate files.
        This avoids duplication because NetBox merges local_context_data into
        config_context automatically.

        Args:
            device: NetBox device object
            **kwargs: Additional parameters (unused)

        Returns:
            Config context dictionary without frr/netplan parameters
        """
        ctx = device.config_context
        if isinstance(ctx, dict):
            ctx = {
                k: v
                for k, v in ctx.items()
                if k not in ("frr_parameters", "netplan_parameters")
            }
        return ctx
