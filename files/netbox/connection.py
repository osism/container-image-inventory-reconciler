# SPDX-License-Identifier: Apache-2.0

"""NetBox API connection management."""

import time
from typing import Optional

from loguru import logger
import pynetbox
import requests

from config import Config
from exceptions import NetBoxConnectionError


class ConnectionManager:
    """Manages NetBox API connections with retry logic."""

    def __init__(self, config: Config):
        self.config = config
        self.api: Optional[pynetbox.api] = None
        self._session: Optional[requests.Session] = None

    def connect(self) -> pynetbox.api:
        """Establish connection to NetBox with retry logic.

        Returns:
            pynetbox.api: Connected NetBox API instance

        Raises:
            NetBoxConnectionError: If connection fails after all retries
        """
        logger.info(f"Connecting to NetBox {self.config.netbox_url}")

        for attempt in range(self.config.retry_attempts):
            try:
                self.api = pynetbox.api(
                    self.config.netbox_url, self.config.netbox_token
                )

                if self.config.ignore_ssl_errors:
                    self._configure_ssl_ignore()

                # Test connection
                self.api.dcim.sites.count()
                logger.debug("Successfully connected to NetBox")
                return self.api

            except Exception as e:
                logger.warning(f"NetBox connection attempt {attempt + 1} failed: {e}")
                if attempt < self.config.retry_attempts - 1:
                    time.sleep(self.config.retry_delay)
                else:
                    raise NetBoxConnectionError(
                        "Failed to connect to NetBox after all retry attempts"
                    ) from e

    def _configure_ssl_ignore(self) -> None:
        """Configure SSL certificate verification ignoring."""
        requests.packages.urllib3.disable_warnings()
        self._session = requests.Session()
        self._session.verify = False
        if self.api:
            self.api.http_session = self._session

    def disconnect(self) -> None:
        """Close connection and cleanup resources."""
        if self._session:
            self._session.close()
            self._session = None
        self.api = None
