# SPDX-License-Identifier: Apache-2.0

"""Base classes for inventory management."""

import ABC

from config import Config


class BaseInventoryComponent(ABC):
    """Base class for inventory components."""

    def __init__(self, config: Config):
        self.config = config
