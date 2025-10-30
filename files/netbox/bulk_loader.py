# SPDX-License-Identifier: Apache-2.0

"""Bulk data loader for NetBox API optimization.

This module provides efficient bulk loading of interfaces and IP addresses
to reduce API calls from O(n*m) to O(1) where n=devices and m=interfaces.

Uses batched loading for both interfaces and IP addresses to avoid HTTP
header size limits when dealing with large numbers of devices and interfaces.

This is a required component throughout the codebase for optimized API access.
"""

from typing import Any, Dict, List

from loguru import logger


class BulkDataLoader:
    """Loads NetBox data in bulk to minimize API calls.

    Uses batched loading for both interfaces and IP addresses to avoid
    HTTP header size limits when dealing with large numbers of devices
    and interfaces.

    Default batch size is 100, which is conservative enough to avoid
    HTTP 431 "Request Header Fields Too Large" errors in most environments.

    This is a required component throughout the codebase that pre-loads all
    interfaces and IP addresses for multiple devices, then provides cached
    access to the data. This reduces the number of API calls from O(n * m)
    to O(1) where n = number of devices and m = average number of interfaces
    per device.

    Example:
        For 100 devices with 10 interfaces each:
        - Without bulk loading: ~1,100 API calls (1 per device + 1 per interface)
        - With bulk loading: 2-3 API calls (1-2 batches for interfaces, 1 for IPs)
        - Expected speedup: 300-500x reduction in API calls

    Attributes:
        api: NetBox API instance
        batch_size: Maximum number of devices/interfaces per API call for batched loading
        device_interfaces: Dictionary mapping device IDs to list of interface objects
        interface_ips: Dictionary mapping interface IDs to list of IP address objects
    """

    # Default batch size for batched loading (conservative to avoid header limits)
    BATCH_SIZE = 100

    def __init__(self, api: Any, batch_size: int = 100) -> None:
        """Initialize the bulk data loader.

        Args:
            api: NetBox API instance (pynetbox.api.Api object)
            batch_size: Maximum number of devices/interfaces per API call (default: 100)
        """
        self.api = api
        self.batch_size = batch_size
        self.device_interfaces: Dict[int, List[Any]] = {}
        self.interface_ips: Dict[int, List[Any]] = {}

    @staticmethod
    def _chunk_list(items: List[Any], chunk_size: int) -> List[List[Any]]:
        """Split a list into chunks of specified size.

        Args:
            items: List to split
            chunk_size: Maximum size of each chunk

        Returns:
            List of chunks
        """
        return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]  # noqa E203

    def load_device_data(self, device_ids: List[int]) -> None:
        """Load all interfaces and IP addresses for multiple devices using batched API calls.

        This method performs bulk loading with batching to minimize API calls
        while avoiding HTTP header size limits:
        - Interfaces loaded in batches of devices (default: 100 devices per call)
        - IP addresses loaded in batches of interfaces (default: 100 interfaces per call)

        Args:
            device_ids: List of NetBox device IDs to load data for

        Raises:
            Exception: If API calls fail (logged but not raised)
        """
        if not device_ids:
            logger.debug("No device IDs provided, skipping bulk load")
            return

        logger.info(f"Bulk loading data for {len(device_ids)} devices")

        try:
            # Bulk load interfaces in batches to avoid HTTP header size limits
            logger.debug(
                f"Fetching interfaces for {len(device_ids)} devices in batches"
            )
            all_interfaces = []

            # Split device IDs into batches
            device_id_batches = self._chunk_list(device_ids, self.batch_size)
            logger.info(
                f"Loading interfaces in {len(device_id_batches)} batches "
                f"of up to {self.batch_size} devices"
            )

            for batch_num, batch_ids in enumerate(device_id_batches, 1):
                try:
                    logger.debug(
                        f"Loading interfaces for batch {batch_num}/{len(device_id_batches)} "
                        f"({len(batch_ids)} devices)"
                    )
                    batch_interfaces = list(
                        self.api.dcim.interfaces.filter(device_id=batch_ids)
                    )
                    all_interfaces.extend(batch_interfaces)
                    logger.debug(
                        f"Batch {batch_num}: loaded {len(batch_interfaces)} interfaces"
                    )
                except Exception as e:
                    logger.error(
                        f"Failed to load interfaces for batch {batch_num}: {e}"
                    )
                    # Continue with other batches even if one fails
                    continue

            logger.info(
                f"Loaded {len(all_interfaces)} interfaces in total "
                f"from {len(device_id_batches)} batches"
            )

            # Group interfaces by device ID
            for interface in all_interfaces:
                device_id = interface.device.id
                if device_id not in self.device_interfaces:
                    self.device_interfaces[device_id] = []
                self.device_interfaces[device_id].append(interface)

            # Extract all interface IDs for IP address lookup
            interface_ids = [interface.id for interface in all_interfaces]

            if interface_ids:
                # Bulk load IP addresses in batches to avoid HTTP header size limits
                logger.debug(
                    f"Fetching IP addresses for {len(interface_ids)} interfaces in batches"
                )
                all_ips = []

                # Split interface IDs into batches
                interface_id_batches = self._chunk_list(interface_ids, self.batch_size)
                logger.info(
                    f"Loading IP addresses in {len(interface_id_batches)} batches of up to {self.batch_size} interfaces"
                )

                for batch_num, batch_ids in enumerate(interface_id_batches, 1):
                    try:
                        logger.debug(
                            f"Loading IP addresses for batch {batch_num}/{len(interface_id_batches)} ({len(batch_ids)} interfaces)"
                        )
                        batch_ips = list(
                            self.api.ipam.ip_addresses.filter(interface_id=batch_ids)
                        )
                        all_ips.extend(batch_ips)
                        logger.debug(
                            f"Batch {batch_num}: loaded {len(batch_ips)} IP addresses"
                        )
                    except Exception as e:
                        logger.error(
                            f"Failed to load IP addresses for batch {batch_num}: {e}"
                        )
                        # Continue with other batches even if one fails
                        continue

                logger.info(
                    f"Loaded {len(all_ips)} IP addresses in total from {len(interface_id_batches)} batches"
                )

                # Group IP addresses by interface ID
                for ip in all_ips:
                    interface_id = ip.assigned_object_id
                    if interface_id not in self.interface_ips:
                        self.interface_ips[interface_id] = []
                    self.interface_ips[interface_id].append(ip)
            else:
                logger.debug("No interfaces found, skipping IP address loading")

        except Exception as e:
            logger.error(f"Error during bulk data loading: {e}")
            # Clear any partial data on error
            self.device_interfaces.clear()
            self.interface_ips.clear()
            raise

    def get_device_interfaces(self, device: Any) -> List[Any]:
        """Get cached interfaces for a device.

        Args:
            device: NetBox device object with an 'id' attribute

        Returns:
            List of interface objects for the device, empty list if not found
        """
        return self.device_interfaces.get(device.id, [])

    def get_interface_ip_addresses(self, interface: Any) -> List[Any]:
        """Get cached IP addresses for an interface.

        Args:
            interface: NetBox interface object with an 'id' attribute

        Returns:
            List of IP address objects for the interface, empty list if not found
        """
        return self.interface_ips.get(interface.id, [])

    def clear(self) -> None:
        """Clear all cached data.

        This method frees memory by clearing the interface and IP address caches.
        """
        self.device_interfaces.clear()
        self.interface_ips.clear()
        logger.debug("Cleared bulk loader cache")

    def get_statistics(self) -> Dict[str, int]:
        """Get statistics about loaded data.

        Returns:
            Dictionary with statistics:
                - devices: Number of devices with cached interfaces
                - interfaces: Total number of cached interfaces
                - ip_addresses: Total number of cached IP addresses
        """
        total_interfaces = sum(
            len(interfaces) for interfaces in self.device_interfaces.values()
        )
        total_ips = sum(len(ips) for ips in self.interface_ips.values())

        return {
            "devices": len(self.device_interfaces),
            "interfaces": total_interfaces,
            "ip_addresses": total_ips,
        }
