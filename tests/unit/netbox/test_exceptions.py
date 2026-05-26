# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/exceptions.py.

Inheritance smoke tests for the NetBox exception hierarchy: every custom
exception must subclass ``NetBoxException`` (and therefore ``Exception``) so
callers can catch the whole family with a single ``except NetBoxException``.
"""

import pytest

from exceptions import NetBoxAPIError, NetBoxConnectionError, NetBoxException


def test_netbox_exception_is_exception_subclass():
    assert issubclass(NetBoxException, Exception)


def test_connection_error_is_netbox_exception_subclass():
    assert issubclass(NetBoxConnectionError, NetBoxException)
    assert issubclass(NetBoxConnectionError, Exception)


def test_api_error_is_netbox_exception_subclass():
    assert issubclass(NetBoxAPIError, NetBoxException)
    assert issubclass(NetBoxAPIError, Exception)


@pytest.mark.parametrize(
    "exc_class",
    [NetBoxException, NetBoxConnectionError, NetBoxAPIError],
)
def test_message_is_preserved(exc_class):
    exc = exc_class("something went wrong")
    assert str(exc) == "something went wrong"


@pytest.mark.parametrize(
    "exc_class",
    [NetBoxConnectionError, NetBoxAPIError],
)
def test_subclasses_caught_as_netbox_exception(exc_class):
    with pytest.raises(NetBoxException):
        raise exc_class("boom")
