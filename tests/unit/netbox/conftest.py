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
* ``make_iface_type`` / ``make_vlan`` / ``make_vlan_group`` / ``make_prefix``
  / ``make_dnsmasq_config`` -- additional shapes consumed by the tier-6
  dnsmasq tests. ``make_interface`` gains the ``type`` / ``label`` / ``name``
  / ``untagged_vlan`` / ``connected_endpoints`` / ``enabled`` attributes the
  dnsmasq interface gating reads, ``make_device`` gains ``device_type`` for
  the MAC-entry fallback and ``make_fake_api`` gains ``prefixes`` to back
  ``ipam.prefixes.filter(tag=...)``. Every addition is keyword-only and
  defaulted so the tier 1-5 callers keep working unchanged.
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


def make_device(
    id, name, *, role=None, site=None, tags=(), custom_fields=None, device_type=None
):
    """Build a NetBox-shaped device stub.

    Only the attributes consulted by the modules under test are populated:
    ``id``, ``name``, ``role``, ``site``, ``tags`` (list of tag stubs),
    ``custom_fields`` (plain dict) and ``device_type``. ``role`` and ``site``
    accept any object exposing a ``.slug`` attribute -- pass ``make_tag("...")``
    for the common case or build a custom ``SimpleNamespace`` when extra fields
    are needed. ``device_type`` defaults to ``None`` and accepts a
    ``SimpleNamespace(slug="...")`` for the dnsmasq MAC-entry device-type
    fallback.
    """
    return SimpleNamespace(
        id=id,
        name=name,
        role=role,
        site=site,
        tags=[make_tag(t) for t in tags],
        custom_fields=custom_fields if custom_fields is not None else {},
        device_type=device_type,
    )


def make_ip(address):
    """Build a NetBox-shaped IP-address stub with the ``.address`` attribute."""
    return SimpleNamespace(address=address)


def make_iface_type(value):
    """Build a NetBox-shaped interface-type stub with the ``.value`` attribute.

    The dnsmasq interface gating tests virtual interfaces via
    ``interface.type.value == "virtual"``.
    """
    return SimpleNamespace(value=value)


def make_vlan(vid, *, group=None):
    """Build a NetBox-shaped VLAN stub.

    Exposes ``vid`` and an optional ``group`` (a ``make_vlan_group(...)`` stub)
    used by the dnsmasq routed-group check.
    """
    return SimpleNamespace(vid=vid, group=group)


def make_vlan_group(name):
    """Build a NetBox-shaped VLAN-group stub with the ``.name`` attribute."""
    return SimpleNamespace(name=name)


def make_prefix(prefix, *, vlan=None):
    """Build a NetBox-shaped OOB network / prefix stub.

    Exposes ``prefix`` (a CIDR string) and an optional ``vlan``
    (a ``make_vlan(...)`` stub).
    """
    return SimpleNamespace(prefix=prefix, vlan=vlan)


def make_interface(
    *,
    id,
    mgmt_only=False,
    tags=(),
    name=None,
    label=None,
    type=None,
    untagged_vlan=None,
    connected_endpoints=None,
    enabled=True,
):
    """Build a NetBox-shaped interface stub.

    Models the attributes ``gnmic_extractor`` reads off an interface (``id``,
    ``mgmt_only`` and ``tags``) plus the attributes the dnsmasq interface
    gating consults: ``name``, ``label``, ``type`` (a ``make_iface_type(...)``
    stub), ``untagged_vlan`` (a ``make_vlan(...)`` stub), ``connected_endpoints``
    and ``enabled``. All dnsmasq attributes are keyword-only and defaulted so
    the tier-3 callers (``make_interface(id=..., mgmt_only=..., tags=...)``)
    keep working unchanged.
    """
    return SimpleNamespace(
        id=id,
        mgmt_only=mgmt_only,
        tags=[make_tag(t) for t in tags],
        name=name,
        label=label,
        type=type,
        untagged_vlan=untagged_vlan,
        connected_endpoints=connected_endpoints,
        enabled=enabled,
    )


def make_fake_api(interfaces=(), ips_by_interface=None, prefixes=()):
    """Build a pynetbox-shaped API session stub.

    Exposes ``dcim.interfaces.filter(device_id=...)`` returning ``interfaces``,
    ``ipam.ip_addresses.filter(interface_id=...)`` returning the addresses
    registered for that interface id in ``ips_by_interface`` (default empty)
    and ``ipam.prefixes.filter(tag=...)`` returning ``prefixes`` (default
    empty), used by the dnsmasq metalbox DHCP-option collector.
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
            prefixes=SimpleNamespace(
                filter=lambda tag: list(prefixes),
            ),
        ),
    )


def make_dnsmasq_config(
    tmp_path,
    *,
    reconciler_mode="manager",
    dnsmasq_lease_time="28d",
    dnsmasq_switch_roles=("leaf",),
):
    """Build a config stub for the dnsmasq modules.

    Mirrors the four ``Config`` attributes the dnsmasq package reads --
    ``reconciler_mode``, ``inventory_path`` (the pytest ``tmp_path`` used as the
    inventory root), ``dnsmasq_lease_time`` and ``dnsmasq_switch_roles`` -- as a
    ``SimpleNamespace`` so tests need not import the real ``Config``.
    """
    return SimpleNamespace(
        reconciler_mode=reconciler_mode,
        inventory_path=tmp_path,
        dnsmasq_lease_time=dnsmasq_lease_time,
        dnsmasq_switch_roles=list(dnsmasq_switch_roles),
    )
