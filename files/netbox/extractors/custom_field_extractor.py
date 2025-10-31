# SPDX-License-Identifier: Apache-2.0

"""Custom field extractor."""

from typing import Any

from .base_extractor import BaseExtractor


class CustomFieldExtractor(BaseExtractor):
    """Extracts custom fields from NetBox devices."""

    def extract(self, device: Any, field_name: str = None, **kwargs) -> Any:
        """Extract a specific custom field from device.

        Args:
            device: NetBox device object
            field_name: Name of the custom field to extract
            **kwargs: Additional parameters (unused)

        Returns:
            Custom field value or None if not found
        """
        if not field_name:
            raise ValueError("field_name parameter is required")

        custom_fields = device.custom_fields or {}
        return custom_fields.get(field_name)
