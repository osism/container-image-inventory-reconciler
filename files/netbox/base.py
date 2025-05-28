# SPDX-License-Identifier: Apache-2.0

"""Base classes for NetBox client implementations."""

from abc import ABC, abstractmethod
from typing import Optional

import pynetbox

from config import Config


class BaseNetBoxClient(ABC):
    """Abstract base class for NetBox client implementations."""

    def __init__(self, config: Config):
        self.config = config
        self.api: Optional[pynetbox.api] = None

    @abstractmethod
    def connect(self) -> None:
        """Establish connection to NetBox."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Close connection to NetBox."""
        pass
