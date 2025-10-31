# SPDX-License-Identifier: Apache-2.0

"""Parallel device processing with configurable concurrency."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List

from loguru import logger


class ParallelDeviceProcessor:
    """Processes devices in parallel with error handling and progress tracking."""

    def __init__(self, max_workers: int = 10, enabled: bool = True):
        """Initialize parallel processor.

        Args:
            max_workers: Maximum number of concurrent workers
            enabled: Whether to use parallel processing (False = sequential)
        """
        self.max_workers = max_workers
        self.enabled = enabled
        self.results: Dict[str, Any] = {}
        self.failures: List[Dict[str, Any]] = []

    def process_devices(
        self, devices: List[Any], process_func: Callable, *args, **kwargs
    ) -> Dict[str, Any]:
        """Process devices in parallel or sequentially.

        Args:
            devices: List of device objects to process
            process_func: Function to call for each device (must accept device as first arg)
            *args, **kwargs: Additional arguments for process_func

        Returns:
            Dictionary with:
            - completed: Number of successful processings
            - failed: Number of failed processings
            - results: Dict of device_name -> result
            - failures: List of failure details
        """
        if not self.enabled or self.max_workers == 1:
            return self._process_sequential(devices, process_func, *args, **kwargs)

        return self._process_parallel(devices, process_func, *args, **kwargs)

    def _process_parallel(
        self, devices: List[Any], process_func: Callable, *args, **kwargs
    ) -> Dict[str, Any]:
        """Process devices in parallel using ThreadPoolExecutor."""
        logger.info(
            f"Processing {len(devices)} devices with {self.max_workers} parallel workers"
        )

        completed = 0
        failed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_device = {
                executor.submit(process_func, device, *args, **kwargs): device
                for device in devices
            }

            # Process completed tasks as they finish
            for future in as_completed(future_to_device):
                device = future_to_device[future]

                try:
                    result = future.result()
                    self.results[device.name] = result
                    completed += 1

                    # Log progress every 10 devices
                    if completed % 10 == 0 or completed == len(devices):
                        logger.info(
                            f"Progress: {completed}/{len(devices)} devices processed "
                            f"({failed} failed)"
                        )

                except Exception as e:
                    failed += 1
                    self.failures.append(
                        {
                            "device": device.name,
                            "device_id": device.id,
                            "error": str(e),
                            "error_type": type(e).__name__,
                        }
                    )
                    logger.error(f"Failed to process device {device.name}: {e}")

        logger.info(
            f"Parallel processing complete: {completed} succeeded, {failed} failed"
        )

        return {
            "completed": completed,
            "failed": failed,
            "results": self.results,
            "failures": self.failures,
        }

    def _process_sequential(
        self, devices: List[Any], process_func: Callable, *args, **kwargs
    ) -> Dict[str, Any]:
        """Process devices sequentially (fallback or when parallel is disabled)."""
        logger.info(f"Processing {len(devices)} devices sequentially")

        completed = 0
        failed = 0

        for device in devices:
            try:
                result = process_func(device, *args, **kwargs)
                self.results[device.name] = result
                completed += 1

                # Log progress every 10 devices
                if completed % 10 == 0 or completed == len(devices):
                    logger.info(
                        f"Progress: {completed}/{len(devices)} devices processed "
                        f"({failed} failed)"
                    )

            except Exception as e:
                failed += 1
                self.failures.append(
                    {
                        "device": device.name,
                        "device_id": device.id,
                        "error": str(e),
                        "error_type": type(e).__name__,
                    }
                )
                logger.error(f"Failed to process device {device.name}: {e}")

        logger.info(
            f"Sequential processing complete: {completed} succeeded, {failed} failed"
        )

        return {
            "completed": completed,
            "failed": failed,
            "results": self.results,
            "failures": self.failures,
        }
