# SPDX-License-Identifier: Apache-2.0

"""Base extractor abstract class."""

from abc import ABC, abstractmethod
from typing import Any


class BaseExtractor(ABC):
    """Abstract base class for all data extractors."""

    @abstractmethod
    def extract(self, device: Any, **kwargs) -> Any:
        """Extract data from a NetBox device.

        Args:
            device: NetBox device object
            **kwargs: Additional parameters for extraction

        Returns:
            Extracted data in appropriate format
        """
        pass
