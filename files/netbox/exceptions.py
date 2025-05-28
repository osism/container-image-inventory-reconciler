# SPDX-License-Identifier: Apache-2.0

"""Custom exceptions for NetBox client operations."""


class NetBoxException(Exception):
    """Base exception for NetBox client errors."""

    pass


class NetBoxConnectionError(NetBoxException):
    """Raised when connection to NetBox fails."""

    pass


class NetBoxAPIError(NetBoxException):
    """Raised when NetBox API returns an error."""

    pass
