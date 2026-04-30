# SPDX-License-Identifier: Apache-2.0

"""Smoke tests verifying the test infrastructure is wired up correctly.

These tests exist so a regression in the harness (broken sys.path, missing
runtime dependency, import-time crash in a netbox module) fails CI loudly
before any per-module test suite runs.
"""

import utils
from exceptions import NetBoxAPIError, NetBoxConnectionError, NetBoxException


def test_deep_merge_is_callable():
    assert callable(utils.deep_merge)


def test_deep_merge_basic():
    assert utils.deep_merge({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}


def test_netbox_exception_hierarchy():
    assert issubclass(NetBoxConnectionError, NetBoxException)
    assert issubclass(NetBoxAPIError, NetBoxException)
