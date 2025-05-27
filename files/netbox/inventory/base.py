# SPDX-License-Identifier: Apache-2.0

"""Base classes for inventory management."""

from abc import ABC

from config import Config


class BaseInventoryComponent(ABC):
    """Base class for inventory components."""

    def __init__(self, config: Config):
        self.config = config
