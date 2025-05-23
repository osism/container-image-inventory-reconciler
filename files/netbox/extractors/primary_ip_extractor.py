# SPDX-License-Identifier: Apache-2.0

"""Primary IP address extractor."""

from typing import Any, Optional

from .base_extractor import BaseExtractor


class PrimaryIPExtractor(BaseExtractor):
    """Extracts primary IP address from NetBox devices."""

    def extract(self, device: Any, **kwargs) -> Optional[str]:
        """Extract primary IP address from device, prioritizing IPv4 over IPv6.

        Args:
            device: NetBox device object
            **kwargs: Additional parameters (unused)

        Returns:
            Primary IP address string without subnet mask, or None if not found
        """
        # Check if device has primary_ip4
        if device.primary_ip4:
            return device.primary_ip4.address.split("/")[0]
        # Fall back to primary_ip6 if no IPv4 is available
        elif device.primary_ip6:
            return device.primary_ip6.address.split("/")[0]
        # Legacy fallback to primary_ip if neither is available
        elif device.primary_ip:
            return device.primary_ip.address.split("/")[0]
        return None
