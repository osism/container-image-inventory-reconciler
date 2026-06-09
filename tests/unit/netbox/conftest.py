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
* ``make_ip`` / ``make_interface`` / ``make_fake_api`` -- factories for the
  IP-address, interface and pynetbox-session shapes used by the tier-3
  extractors (primary_ip and gnmic). ``make_interface`` / ``make_fake_api``
  model the ``dcim.interfaces.filter`` / ``ipam.ip_addresses.filter`` lookups
  performed by ``gnmic_extractor`` and are reused by tiers 4-9.
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


def make_ip(address):
    """Build a NetBox-shaped IP-address stub with the ``.address`` attribute."""
    return SimpleNamespace(address=address)


def make_interface(*, id, mgmt_only, tags=()):
    """Build a NetBox-shaped interface stub.

    Models only the attributes ``gnmic_extractor`` reads off an interface:
    ``id``, ``mgmt_only`` and ``tags`` (list of tag stubs).
    """
    return SimpleNamespace(
        id=id,
        mgmt_only=mgmt_only,
        tags=[make_tag(t) for t in tags],
    )


def make_fake_api(interfaces=(), ips_by_interface=None):
    """Build a pynetbox-shaped API session stub.

    Exposes ``dcim.interfaces.filter(device_id=...)`` returning ``interfaces``
    and ``ipam.ip_addresses.filter(interface_id=...)`` returning the addresses
    registered for that interface id in ``ips_by_interface`` (default empty).
    """
    ips_by_interface = ips_by_interface or {}
    return SimpleNamespace(
        dcim=SimpleNamespace(
            interfaces=SimpleNamespace(
                filter=lambda device_id: list(interfaces),
            ),
        ),
        ipam=SimpleNamespace(
            ip_addresses=SimpleNamespace(
                filter=lambda interface_id: list(
                    ips_by_interface.get(interface_id, [])
                ),
            ),
        ),
    )
