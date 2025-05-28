# SPDX-License-Identifier: Apache-2.0

"""Custom field extractor."""

from typing import Any

from .base_extractor import BaseExtractor


class CustomFieldExtractor(BaseExtractor):
    """Extracts custom fields from NetBox devices."""

    def __init__(self, file_cache=None):
        """Initialize the extractor.

        Args:
            file_cache: FileCache instance for persistent caching
        """
        self.file_cache = file_cache

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

        # Check file cache first if available
        if self.file_cache:
            cached_value = self.file_cache.get_custom_field(device.name, field_name)
            if cached_value is not None:
                return cached_value

        custom_fields = device.custom_fields or {}
        return custom_fields.get(field_name)
