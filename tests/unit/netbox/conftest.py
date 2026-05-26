# SPDX-License-Identifier: Apache-2.0

"""Shared test support for the netbox unit tests.

Provides:

* ``FakeSettings`` -- a minimal dict wrapper that stands in for the dynaconf
  ``SETTINGS`` instance. The production code paths under test only ever call
  ``SETTINGS.get(key, default)``, so a thin ``.get()``-only object is enough
  and keeps tests isolated from real environment variables.
* ``make_tag`` / ``make_device`` -- tiny factories producing ``SimpleNamespace``
  stand-ins for the pynetbox device and tag objects exercised by the tier-2
  modules (filters, device_mapping, parallel_processor). The factories
  intentionally model only the attributes those modules read.
"""

from types import SimpleNamespace


class FakeSettings:
    """Minimal stand-in for the dynaconf ``SETTINGS`` object."""

    def __init__(self, values=None):
        self._values = dict(values or {})

    def get(self, key, default=None):
        return self._values.get(key, default)


def make_tag(slug):
    """Build a NetBox-shaped tag stub with the ``.slug`` attribute."""
    return SimpleNamespace(slug=slug)


def make_device(id, name, *, role=None, site=None, tags=(), custom_fields=None):
    """Build a NetBox-shaped device stub.

    Only the attributes consulted by the modules under test are populated:
    ``id``, ``name``, ``role``, ``site``, ``tags`` (list of tag stubs) and
    ``custom_fields`` (plain dict). ``role`` and ``site`` accept any object
    exposing a ``.slug`` attribute -- pass ``make_tag("...")`` for the common
    case or build a custom ``SimpleNamespace`` when extra fields are needed.
    """
    return SimpleNamespace(
        id=id,
        name=name,
        role=role,
        site=site,
        tags=[make_tag(t) for t in tags],
        custom_fields=custom_fields if custom_fields is not None else {},
    )
