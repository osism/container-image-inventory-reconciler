# SPDX-License-Identifier: Apache-2.0

"""Ceph parameters extractor."""

from typing import Any, Dict, Optional

from .base_extractor import BaseExtractor


class CephExtractor(BaseExtractor):
    """Extracts Ceph parameters from NetBox devices.

    Initially, Ceph parameters (e.g. "ceph_osd_devices") are supplied via
    Config Context under the "ceph_parameters" key and are passed straight
    through into the inventory. Once the Ceph devices are configured, the
    enriched values can be written to the "ceph_parameters" custom field
    on the device. Once that custom field is set, it takes priority over
    the Config Context value and is used instead.

    The extractor itself never writes back to NetBox
    """

    def extract(self, device: Any, **kwargs) -> Optional[Dict[str, Any]]:
        """Extract Ceph parameters from device.

        Args:
            device: NetBox device object
            **kwargs: Additional parameters (unused)

        Returns:
            Ceph parameters dictionary, or None if neither source is set
        """
        custom_fields = device.custom_fields or {}
        custom_field_value = custom_fields.get("ceph_parameters")
        if isinstance(custom_field_value, dict):
            return custom_field_value

        config_context = device.config_context
        if isinstance(config_context, dict):
            cc_value = config_context.get("ceph_parameters")
            if isinstance(cc_value, dict):
                return cc_value

        return None
