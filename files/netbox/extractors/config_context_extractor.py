# SPDX-License-Identifier: Apache-2.0

"""Config context extractor."""

from typing import Any, Dict

from .base_extractor import BaseExtractor


class ConfigContextExtractor(BaseExtractor):
    """Extracts config context from NetBox devices."""

    def extract(self, device: Any, **kwargs) -> Dict[str, Any]:
        """Extract config context from device.

        Args:
            device: NetBox device object
            **kwargs: Additional parameters (unused)

        Returns:
            Config context dictionary
        """
        return device.config_context
