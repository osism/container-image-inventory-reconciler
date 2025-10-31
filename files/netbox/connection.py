# SPDX-License-Identifier: Apache-2.0

"""NetBox API connection management."""

import time
from typing import Optional

from loguru import logger
import pynetbox
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import Config
from exceptions import NetBoxConnectionError


class ConnectionManager:
    """Manages NetBox API connections with retry logic."""

    def __init__(self, config: Config):
        self.config = config
        self.api: Optional[pynetbox.api] = None
        self._session: Optional[requests.Session] = None

    def _configure_session(self) -> requests.Session:
        """Configure requests session with connection pooling and retry logic.

        Returns:
            requests.Session: Configured session with optimized connection pool

        Notes:
            - Pool connections default to 10, configurable via pool_connections
            - Pool maxsize automatically scales with max_workers (default: 50)
            - Retry strategy with exponential backoff for server errors
            - SSL verification can be disabled via ignore_ssl_errors config
        """
        session = requests.Session()

        # Configure retry strategy with exponential backoff
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=[
                "HEAD",
                "GET",
                "OPTIONS",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
            ],
        )

        # Configure connection pool size
        pool_connections = self.config.pool_connections
        pool_maxsize = max(self.config.pool_maxsize, self.config.max_workers * 2)

        logger.debug(
            f"Configuring session pool: connections={pool_connections}, "
            f"maxsize={pool_maxsize}, max_workers={self.config.max_workers}"
        )

        # Create adapter with connection pooling
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy,
        )

        # Mount adapter for both HTTP and HTTPS
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Configure SSL verification
        if self.config.ignore_ssl_errors:
            requests.packages.urllib3.disable_warnings()
            session.verify = False
            logger.debug("SSL certificate verification disabled")

        return session

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
                # Configure session with connection pooling
                self._session = self._configure_session()

                # Create NetBox API instance with configured session
                self.api = pynetbox.api(
                    self.config.netbox_url, self.config.netbox_token
                )
                self.api.http_session = self._session

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

    def disconnect(self) -> None:
        """Close connection and cleanup resources."""
        if self._session:
            self._session.close()
            self._session = None
        self.api = None
