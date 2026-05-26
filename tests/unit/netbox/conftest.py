# SPDX-License-Identifier: Apache-2.0

"""Shared test support for the netbox unit tests.

Provides ``FakeSettings``, a minimal dict wrapper that stands in for the
dynaconf ``SETTINGS`` instance. The production code paths under test only
ever call ``SETTINGS.get(key, default)``, so a thin ``.get()``-only object
is enough and keeps tests isolated from real environment variables.
"""


class FakeSettings:
    """Minimal stand-in for the dynaconf ``SETTINGS`` object."""

    def __init__(self, values=None):
        self._values = dict(values or {})

    def get(self, key, default=None):
        return self._values.get(key, default)
