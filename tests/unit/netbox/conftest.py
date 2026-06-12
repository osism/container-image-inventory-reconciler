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
* ``make_ip`` / ``make_interface`` / ``make_vlan`` / ``make_fake_api`` --
  factories for the IP-address, interface, VLAN and pynetbox-session shapes
  used by the tier-3 extractors (primary_ip and gnmic) and the tier-4
  bulk-loader / connection modules. ``make_interface`` / ``make_fake_api``
  model the ``dcim.interfaces.filter`` / ``ipam.ip_addresses.filter`` lookups
  performed by ``gnmic_extractor`` and are reused by tiers 4-9. The tier-4
  attributes (interface ``name`` / ``mac_address`` / ``untagged_vlan`` /
  ``device`` and IP ``assigned_object_id``) are keyword-only and defaulted so
  the tier-3 call sites keep working unchanged.
* ``make_iface_type`` / ``make_vrf`` and the tier-5 ``make_interface``
  attributes (``label``, ``type``, ``vrf``, ``connected_endpoints``,
  ``enabled``, ``parent``, ``lag``, ``mtu``, ``mac_address``,
  ``untagged_vlan``, ``device``, ``custom_fields``) model the richer interface
  shapes the large ``frr_extractor`` / ``netplan_extractor`` walk. ``make_device``
  gains a ``config_context`` keyword and ``make_fake_api`` a ``devices_by_id``
  mapping backing the ``dcim.devices.get(id)`` lookup ``frr_extractor`` uses for
  remote-AS resolution. All additions are keyword-only and defaulted, so the
  tier 0-4 tests keep passing unchanged.
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
    id, name, *, role=None, site=None, tags=(), custom_fields=None, config_context=None
):
    """Build a NetBox-shaped device stub.

    Only the attributes consulted by the modules under test are populated:
    ``id``, ``name``, ``role``, ``site``, ``tags`` (list of tag stubs),
    ``custom_fields`` (plain dict) and ``config_context`` (plain dict or
    ``None``). ``role`` and ``site`` accept any object exposing a ``.slug``
    attribute -- pass ``make_tag("...")`` for the common case or build a custom
    ``SimpleNamespace`` when extra fields are needed. ``config_context`` carries
    the deep-merge overrides and ``frr_type`` / ``_segment_default_mtu`` keys the
    tier-5 extractors read.
    """
    return SimpleNamespace(
        id=id,
        name=name,
        role=role,
        site=site,
        tags=[make_tag(t) for t in tags],
        custom_fields=custom_fields if custom_fields is not None else {},
        config_context=config_context,
    )


def make_ip(address, *, assigned_object_id=None):
    """Build a NetBox-shaped IP-address stub.

    Exposes ``.address`` (read by the primary-IP / gnmic extractors and
    ``interfaces``) and ``.assigned_object_id`` -- the interface id that
    ``bulk_loader`` groups IP addresses by. ``assigned_object_id`` is
    keyword-only and defaulted so the tier-3 call sites keep working.
    """
    return SimpleNamespace(address=address, assigned_object_id=assigned_object_id)


def make_vlan(vid):
    """Build a NetBox-shaped VLAN stub with the ``.vid`` attribute."""
    return SimpleNamespace(vid=vid)


def make_iface_type(value):
    """Build a NetBox interface-type stub exposing ``.value``.

    Mirrors ``interface.type.value`` (e.g. ``"virtual"``, ``"lag"``,
    ``"1000base-t"``) that the tier-5 extractors branch on.
    """
    return SimpleNamespace(value=value)


def make_vrf(name, *, rd=None):
    """Build a NetBox-VRF-shaped stub exposing ``.name`` and ``.rd``."""
    return SimpleNamespace(name=name, rd=rd)


def make_interface(
    *,
    id,
    mgmt_only=False,
    tags=(),
    name=None,
    mac_address=None,
    untagged_vlan=None,
    device=None,
    label=None,
    type=None,
    vrf=None,
    connected_endpoints=None,
    enabled=True,
    parent=None,
    lag=None,
    mtu=None,
    custom_fields=None,
):
    """Build a NetBox-shaped interface stub.

    The tier-3 modules (``gnmic_extractor``) read only ``id``, ``mgmt_only``
    and ``tags``; the tier-4 modules (``interfaces`` / ``bulk_loader``) also
    read ``name`` (defaults to ``f"eth{id}"``), ``mac_address``,
    ``untagged_vlan`` (a stub with ``.vid``) and ``device``; the tier-5
    extractors (``frr_extractor`` / ``netplan_extractor``) additionally consult
    ``label``, ``type`` (a :func:`make_iface_type` stub), ``vrf`` (a
    :func:`make_vrf` stub), ``connected_endpoints`` (an iterable of endpoint
    stubs -- a connected endpoint doubles as the remote interface, so a
    :func:`make_interface` works there too), ``enabled``, ``parent`` (another
    interface stub), ``lag`` (a back-reference stub with ``.id``), ``mtu`` and
    ``custom_fields`` (plain dict); ``device`` doubles as the remote device an
    endpoint resolves to. Every attribute beyond the tier-3 set is keyword-only
    and defaulted -- including ``mgmt_only`` -- so the tier-3 callers keep
    working unchanged.
    """
    return SimpleNamespace(
        id=id,
        mgmt_only=mgmt_only,
        tags=[make_tag(t) for t in tags],
        name=name if name is not None else f"eth{id}",
        mac_address=mac_address,
        untagged_vlan=untagged_vlan,
        device=device,
        label=label,
        type=type,
        vrf=vrf,
        connected_endpoints=connected_endpoints,
        enabled=enabled,
        parent=parent,
        lag=lag,
        mtu=mtu,
        custom_fields=custom_fields if custom_fields is not None else {},
    )


def make_fake_api(interfaces=(), ips_by_interface=None, devices_by_id=None):
    """Build a pynetbox-shaped API session stub.

    Exposes ``dcim.interfaces.filter(device_id=...)`` returning ``interfaces``,
    ``ipam.ip_addresses.filter(interface_id=...)`` returning the addresses
    registered for that interface id in ``ips_by_interface`` (default empty),
    and ``dcim.devices.get(id)`` returning the device registered in
    ``devices_by_id`` (default empty) -- the lookup ``frr_extractor`` uses to
    fetch a remote device's custom fields for cached-AS resolution.
    """
    ips_by_interface = ips_by_interface or {}
    devices_by_id = devices_by_id or {}
    return SimpleNamespace(
        dcim=SimpleNamespace(
            interfaces=SimpleNamespace(
                filter=lambda device_id: list(interfaces),
            ),
            devices=SimpleNamespace(
                get=lambda id: devices_by_id.get(id),
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
