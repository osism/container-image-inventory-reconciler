# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/extractors/netplan_extractor.py.

The extractor turns a device's NetBox interfaces into the auto-generated
``netplan_parameters`` (network_ethernets / dummy_devices / vlans / tunnels /
bonds / vrfs). It reads interfaces and IP addresses through a ``BulkDataLoader``
and writes the result back through a ``NetBoxClient``.

The original LAG / bond section (``TestBond*``) predates the shared conftest
factories and keeps its own thin file-local stubs (``_iface`` /
``_FakeBulkLoader`` / ``_FakeNetBoxClient``); a LAG is modelled as an interface
of ``type == "lag"`` whose members carry a ``lag`` back-ref. The newer helper
and full-``extract`` sections below use the shared ``make_*`` factories with a
pre-seeded real ``BulkDataLoader`` and a ``MagicMock`` netbox client, consistent
with the tier-5 frr_extractor tests. The module-level ``loguru`` logger is
patched with a ``MagicMock`` only where a log assertion documents the branch
taken.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from bulk_loader import BulkDataLoader
from config import DEFAULT_METALBOX_IPV6
from extractors.netplan_extractor import NetplanExtractor

from .conftest import (
    make_device,
    make_fake_api,
    make_iface_type,
    make_interface,
    make_ip,
    make_tag,
    make_vrf,
)


def _tag(slug="managed-by-osism"):
    return SimpleNamespace(slug=slug)


def _vrf(name="vrf42"):
    """Build a NetBox-VRF-shaped stub; table id is parsed from the name (vrfN)."""
    return SimpleNamespace(name=name, rd=None)


def _iface(
    id,
    name,
    *,
    label=None,
    type_value="1000base-t",
    mac=None,
    mtu=None,
    lag=None,
    enabled=True,
    mgmt_only=False,
    vrf=None,
    tags=("managed-by-osism",),
    custom_fields=None,
):
    """Build a NetBox-interface-shaped stub with the attributes the extractor reads."""
    return SimpleNamespace(
        id=id,
        name=name,
        label=label if label is not None else name,
        type=SimpleNamespace(value=type_value),
        mac_address=mac,
        mtu=mtu,
        enabled=enabled,
        mgmt_only=mgmt_only,
        vrf=vrf,
        untagged_vlan=None,
        parent=None,
        connected_endpoints=None,
        lag=lag,
        tags=[_tag(t) for t in tags],
        custom_fields=custom_fields if custom_fields is not None else {},
    )


class _FakeBulkLoader:
    def __init__(self, interfaces, ips=None):
        self._interfaces = interfaces
        self._ips = ips or {}

    def get_device_interfaces(self, device):
        return self._interfaces

    def get_interface_ip_addresses(self, interface):
        return self._ips.get(interface.id, [])


class _FakeNetBoxClient:
    def __init__(self):
        self.written = []

    def update_device_custom_field(self, device, field, value):
        self.written.append((field, value))
        return True


def _device():
    return SimpleNamespace(
        id=1, name="server1", config_context={}, role=None, custom_fields={}
    )


def _extract(interfaces, ips=None):
    bulk = _FakeBulkLoader(interfaces, ips)
    client = _FakeNetBoxClient()
    extractor = NetplanExtractor(api=object(), netbox_client=client, bulk_loader=bulk)
    return extractor.extract(_device())


class TestBondGeneration:
    def test_lacp_bond_is_generated_from_lag_and_members(self):
        lag = _iface(10, "bond0", type_value="lag", mac=None, mtu=9000)
        m1 = _iface(
            1,
            "eno8303",
            mac="AA:BB:CC:00:00:01",
            mtu=9000,
            lag=SimpleNamespace(id=10, name="bond0"),
        )
        m2 = _iface(
            2,
            "eno8403",
            mac="AA:BB:CC:00:00:02",
            mtu=9000,
            lag=SimpleNamespace(id=10, name="bond0"),
        )
        ips = {10: [SimpleNamespace(address="10.0.0.5/24")]}

        result = _extract([lag, m1, m2], ips)

        # Bond carries the LACP defaults, MTU and the IP of the LAG interface.
        assert result["network_bonds"]["bond0"] == {
            "interfaces": ["eno8303", "eno8403"],
            "parameters": {
                "mode": "802.3ad",
                "lacp-rate": "fast",
                "mii-monitor-interval": 100,
                "transmit-hash-policy": "layer3+4",
            },
            "mtu": 9000,
            "addresses": ["10.0.0.5/24"],
        }

        # Members are renamed via their MAC but must not carry any IPs/DHCP.
        assert result["network_ethernets"]["eno8303"] == {
            "match": {"macaddress": "aa:bb:cc:00:00:01"},
            "set-name": "eno8303",
            "mtu": 9000,
        }
        assert "addresses" not in result["network_ethernets"]["eno8403"]
        assert "dhcp4" not in result["network_ethernets"]["eno8403"]

    def test_custom_field_overrides_parameters_for_active_backup(self):
        active_backup = {
            "parameters": {
                "mode": "active-backup",
                "primary": "eno8303",
                "mii-monitor-interval": 100,
                "fail-over-mac-policy": "active",
            }
        }
        lag = _iface(
            10,
            "bond0",
            type_value="lag",
            mtu=9000,
            custom_fields={"netplan_parameters": active_backup},
        )
        m1 = _iface(
            1,
            "eno8303",
            mac="AA:BB:CC:00:00:01",
            lag=SimpleNamespace(id=10, name="bond0"),
        )
        m2 = _iface(
            2,
            "eno8403",
            mac="AA:BB:CC:00:00:02",
            lag=SimpleNamespace(id=10, name="bond0"),
        )

        result = _extract([lag, m1, m2])

        # The explicit parameters fully replace the LACP defaults.
        assert (
            result["network_bonds"]["bond0"]["parameters"]
            == active_backup["parameters"]
        )
        assert result["network_bonds"]["bond0"]["interfaces"] == ["eno8303", "eno8403"]

    def test_member_of_unmanaged_lag_falls_back_to_regular_ethernet(self):
        # LAG parent without the managed-by-osism tag -> not treated as a bond.
        m1 = _iface(
            1,
            "eno8303",
            mac="AA:BB:CC:00:00:01",
            mtu=9000,
            lag=SimpleNamespace(id=99, name="bond9"),
        )
        ips = {1: [SimpleNamespace(address="10.0.0.5/24")]}

        result = _extract([m1], ips)

        assert "network_bonds" not in result
        # As a plain ethernet it keeps its own addresses.
        assert result["network_ethernets"]["eno8303"]["addresses"] == ["10.0.0.5/24"]


class TestBondEligibilityGates:
    """Edge cases for the LAG / member eligibility gates (review findings 1-3)."""

    def test_mgmt_only_lag_is_not_emitted_as_a_bond(self):
        # Finding 1: a mgmt_only LAG must not become an active bond.
        lag = _iface(10, "bond0", type_value="lag", mtu=9000, mgmt_only=True)
        m1 = _iface(
            1,
            "eno8303",
            mac="AA:BB:CC:00:00:01",
            mtu=9000,
            lag=SimpleNamespace(id=10, name="bond0"),
        )

        result = _extract([lag, m1])

        assert result is None or "network_bonds" not in result

    def test_disabled_lag_is_not_emitted_as_a_bond(self):
        # Finding 1: a disabled LAG must not become an active bond, and must not
        # leak into network_ethernets as an activation-mode: off entry.
        lag = _iface(
            10,
            "bond0",
            type_value="lag",
            mac="AA:BB:CC:00:00:99",
            mtu=9000,
            enabled=False,
        )
        m1 = _iface(
            1,
            "eno8303",
            mac="AA:BB:CC:00:00:01",
            mtu=9000,
            lag=SimpleNamespace(id=10, name="bond0"),
        )

        result = _extract([lag, m1])

        assert result is None or "network_bonds" not in result
        if result:
            assert "bond0" not in result.get("network_ethernets", {})

    def test_disabled_member_is_dropped_not_orphaned(self):
        # Finding 2: a disabled member of a 2-member bond is excluded from the
        # bond's interfaces AND must not be emitted as a dangling ethernet.
        lag = _iface(10, "bond0", type_value="lag", mtu=9000)
        m_up = _iface(
            1,
            "eno8303",
            mac="AA:BB:CC:00:00:01",
            mtu=9000,
            lag=SimpleNamespace(id=10, name="bond0"),
        )
        m_down = _iface(
            2,
            "eno8403",
            mac="AA:BB:CC:00:00:02",
            mtu=9000,
            enabled=False,
            lag=SimpleNamespace(id=10, name="bond0"),
        )

        result = _extract([lag, m_up, m_down])

        assert result["network_bonds"]["bond0"]["interfaces"] == ["eno8303"]
        # The disabled member is neither in the bond nor a standalone ethernet.
        assert "eno8403" not in result["network_ethernets"]

    def test_bond_with_no_eligible_members_is_skipped(self):
        # Finding 3: a managed LAG whose members are all ineligible must not emit
        # an empty interfaces list (invalid netplan) - the bond is skipped.
        lag = _iface(10, "bond0", type_value="lag", mtu=9000)
        # Member without the managed-by-osism tag -> not collected as a member.
        m1 = _iface(
            1,
            "eno8303",
            mac="AA:BB:CC:00:00:01",
            mtu=9000,
            tags=(),
            lag=SimpleNamespace(id=10, name="bond0"),
        )

        result = _extract([lag, m1])

        assert result is None or "network_bonds" not in result


class TestBondCustomFieldOverrides:
    """Custom-field override edge cases (review findings 4 and 7)."""

    def test_member_custom_field_cannot_reintroduce_l3_or_clobber_identity(self):
        # Finding 4: a member's netplan_parameters must not reintroduce
        # addresses/dhcp or overwrite the MAC-rename identity (match/set-name).
        member_cf = {
            "netplan_parameters": {
                "addresses": ["10.9.9.9/24"],
                "dhcp4": True,
                "match": {"macaddress": "ff:ff:ff:ff:ff:ff"},
                "set-name": "hijacked",
                "wakeonlan": True,  # a harmless key that should pass through
            }
        }
        lag = _iface(10, "bond0", type_value="lag", mtu=9000)
        m1 = _iface(
            1,
            "eno8303",
            mac="AA:BB:CC:00:00:01",
            mtu=9000,
            lag=SimpleNamespace(id=10, name="bond0"),
            custom_fields=member_cf,
        )

        result = _extract([lag, m1])

        eth = result["network_ethernets"]["eno8303"]
        assert eth["match"] == {"macaddress": "aa:bb:cc:00:00:01"}
        assert eth["set-name"] == "eno8303"
        assert "addresses" not in eth
        assert "dhcp4" not in eth
        # The non-conflicting key is still applied.
        assert eth["wakeonlan"] is True

    def test_lag_custom_field_cannot_override_auto_detected_members(self):
        # Finding 7: the auto-detected membership is authoritative; an
        # "interfaces" key in the LAG custom field is ignored.
        lag = _iface(
            10,
            "bond0",
            type_value="lag",
            mtu=9000,
            custom_fields={"netplan_parameters": {"interfaces": ["wrong0"]}},
        )
        m1 = _iface(
            1,
            "eno8303",
            mac="AA:BB:CC:00:00:01",
            mtu=9000,
            lag=SimpleNamespace(id=10, name="bond0"),
        )

        result = _extract([lag, m1])

        assert result["network_bonds"]["bond0"]["interfaces"] == ["eno8303"]


class TestBondVrfMembership:
    """VRF-on-bond vs VRF-on-member (review finding 8)."""

    def test_vrf_assignment_on_lag_adds_the_bond_to_the_vrf(self):
        lag = _iface(10, "bond0", type_value="lag", mtu=9000, vrf=_vrf("vrf42"))
        m1 = _iface(
            1,
            "eno8303",
            mac="AA:BB:CC:00:00:01",
            mtu=9000,
            lag=SimpleNamespace(id=10, name="bond0"),
        )

        result = _extract([lag, m1])

        assert result["network_vrfs"]["vrf42"]["table"] == 42
        assert result["network_vrfs"]["vrf42"]["interfaces"] == ["bond0"]

    def test_vrf_assignment_on_member_is_not_registered(self):
        # The bond carries L3 config, not its members: a VRF on a member must
        # not create a VRF interface entry.
        lag = _iface(10, "bond0", type_value="lag", mtu=9000)
        m1 = _iface(
            1,
            "eno8303",
            mac="AA:BB:CC:00:00:01",
            mtu=9000,
            vrf=_vrf("vrf42"),
            lag=SimpleNamespace(id=10, name="bond0"),
        )

        result = _extract([lag, m1])

        # The member must not appear in any VRF, and no VRF is created for it.
        assert "network_vrfs" not in result or "eno8303" not in [
            iface
            for vrf in result["network_vrfs"].values()
            for iface in vrf["interfaces"]
        ]


# ===========================================================================
# Tier-5 helper- and full-extract coverage (shared conftest factories).
#
# The classes below use the shared make_* factories with a pre-seeded real
# BulkDataLoader and a MagicMock netbox client, rather than the file-local
# bond stubs above.
# ===========================================================================


@pytest.fixture
def mock_logger(monkeypatch):
    """Replace the module-level loguru logger with a MagicMock."""
    logger = MagicMock()
    monkeypatch.setattr("extractors.netplan_extractor.logger", logger)
    return logger


def _raise(*args, **kwargs):
    raise RuntimeError("boom")


def _extractor(*, api=None, netbox_client=None, loader=None):
    """Build a NetplanExtractor with a fresh, empty BulkDataLoader by default."""
    if loader is None:
        loader = BulkDataLoader(make_fake_api())
    return NetplanExtractor(api=api, netbox_client=netbox_client, bulk_loader=loader)


def _loader_with(device, interfaces, ips_by_id=None):
    """Build a real BulkDataLoader pre-seeded for a single device."""
    loader = BulkDataLoader(make_fake_api())
    loader.device_interfaces[device.id] = list(interfaces)
    for iface_id, ips in (ips_by_id or {}).items():
        loader.interface_ips[iface_id] = list(ips)
    return loader


# ---------------------------------------------------------------------------
# NetplanExtractor.__init__
# ---------------------------------------------------------------------------


class TestNetplanInit:
    def test_stores_collaborators(self):
        api = object()
        client = object()
        loader = BulkDataLoader(make_fake_api())
        ex = NetplanExtractor(api=api, netbox_client=client, bulk_loader=loader)
        assert ex.api is api
        assert ex.netbox_client is client
        assert ex.bulk_loader is loader


# ---------------------------------------------------------------------------
# NetplanExtractor._is_connected_to_switch
# ---------------------------------------------------------------------------


class TestIsConnectedToSwitch:
    def test_missing_attr_returns_false(self):
        assert (
            _extractor()._is_connected_to_switch(SimpleNamespace(), ["leaf"]) is False
        )

    def test_empty_endpoints_returns_false(self):
        iface = make_interface(id=1, connected_endpoints=[])
        assert _extractor()._is_connected_to_switch(iface, ["leaf"]) is False

    def test_endpoint_without_device_returns_false(self):
        iface = make_interface(id=1, connected_endpoints=[SimpleNamespace()])
        assert _extractor()._is_connected_to_switch(iface, ["leaf"]) is False

    def test_device_without_role_returns_false(self):
        ep = SimpleNamespace(device=SimpleNamespace())  # device present, no role
        iface = make_interface(id=1, connected_endpoints=[ep])
        assert _extractor()._is_connected_to_switch(iface, ["leaf"]) is False

    def test_switch_role_returns_true(self):
        ep = SimpleNamespace(device=make_device(2, "sw", role=make_tag("leaf")))
        iface = make_interface(id=1, connected_endpoints=[ep])
        assert _extractor()._is_connected_to_switch(iface, ["leaf"]) is True

    def test_non_switch_role_returns_false(self):
        ep = SimpleNamespace(device=make_device(2, "srv", role=make_tag("compute")))
        iface = make_interface(id=1, connected_endpoints=[ep])
        assert _extractor()._is_connected_to_switch(iface, ["leaf"]) is False


# ---------------------------------------------------------------------------
# NetplanExtractor._interface_has_ip_addresses
# ---------------------------------------------------------------------------


class TestInterfaceHasIpAddresses:
    def test_no_api_returns_false(self):
        iface = make_interface(id=1)
        assert _extractor(api=None)._interface_has_ip_addresses(iface) is False

    def test_ips_present_returns_true(self):
        iface = make_interface(id=1)
        loader = BulkDataLoader(make_fake_api())
        loader.interface_ips[1] = [make_ip("10.0.0.1/24")]
        assert (
            _extractor(api=object(), loader=loader)._interface_has_ip_addresses(iface)
            is True
        )

    def test_no_ips_returns_false(self):
        iface = make_interface(id=1)
        assert _extractor(api=object())._interface_has_ip_addresses(iface) is False

    def test_loader_raising_returns_false(self, monkeypatch):
        iface = make_interface(id=1)
        loader = BulkDataLoader(make_fake_api())
        monkeypatch.setattr(loader, "get_interface_ip_addresses", _raise)
        assert (
            _extractor(api=object(), loader=loader)._interface_has_ip_addresses(iface)
            is False
        )


# ---------------------------------------------------------------------------
# NetplanExtractor._collect_addresses
# ---------------------------------------------------------------------------


class TestCollectAddresses:
    def test_returns_all_addresses_with_prefix(self):
        iface = make_interface(id=1)
        loader = BulkDataLoader(make_fake_api())
        loader.interface_ips[1] = [make_ip("10.0.0.1/24"), make_ip("2001:db8::1/64")]
        assert _extractor(loader=loader)._collect_addresses(iface) == [
            "10.0.0.1/24",
            "2001:db8::1/64",
        ]

    def test_falsy_address_skipped(self):
        iface = make_interface(id=1)
        loader = BulkDataLoader(make_fake_api())
        loader.interface_ips[1] = [make_ip(""), make_ip("10.0.0.1/24")]
        assert _extractor(loader=loader)._collect_addresses(iface) == ["10.0.0.1/24"]

    def test_loader_raising_returns_empty(self, monkeypatch):
        iface = make_interface(id=1)
        loader = BulkDataLoader(make_fake_api())
        monkeypatch.setattr(loader, "get_interface_ip_addresses", _raise)
        assert _extractor(loader=loader)._collect_addresses(iface) == []


# ---------------------------------------------------------------------------
# NetplanExtractor._resolve_mtu
# ---------------------------------------------------------------------------


class TestResolveMtu:
    def test_mtu_set_is_returned(self):
        assert _extractor()._resolve_mtu(make_interface(id=1, mtu=1500), 9100) == 1500

    def test_mtu_none_uses_default(self):
        assert _extractor()._resolve_mtu(make_interface(id=1, mtu=None), 9100) == 9100

    def test_mtu_attr_absent_uses_default(self):
        assert _extractor()._resolve_mtu(SimpleNamespace(), 9100) == 9100


# ---------------------------------------------------------------------------
# NetplanExtractor._get_netplan_parameters
# ---------------------------------------------------------------------------


class TestGetNetplanParameters:
    def test_no_custom_fields_attr_returns_none(self):
        assert _extractor()._get_netplan_parameters(SimpleNamespace()) is None

    def test_empty_custom_fields_returns_none(self):
        iface = make_interface(id=1, custom_fields={})
        assert _extractor()._get_netplan_parameters(iface) is None

    def test_dict_value_is_returned(self):
        iface = make_interface(
            id=1, custom_fields={"netplan_parameters": {"mtu": 1500}}
        )
        assert _extractor()._get_netplan_parameters(iface) == {"mtu": 1500}

    def test_non_dict_value_returns_none(self):
        iface = make_interface(id=1, custom_fields={"netplan_parameters": "nope"})
        assert _extractor()._get_netplan_parameters(iface) is None

    def test_empty_dict_value_returns_none(self):
        iface = make_interface(id=1, custom_fields={"netplan_parameters": {}})
        assert _extractor()._get_netplan_parameters(iface) is None


# ---------------------------------------------------------------------------
# NetplanExtractor._apply_netplan_overrides
# ---------------------------------------------------------------------------


class TestApplyNetplanOverrides:
    def test_non_protected_keys_are_copied(self):
        config = {"mtu": 9100}
        _extractor()._apply_netplan_overrides(config, {"mtu": 1500, "wakeonlan": True})
        assert config == {"mtu": 1500, "wakeonlan": True}

    def test_protected_keys_are_skipped_and_warned(self, mock_logger):
        config = {}
        _extractor()._apply_netplan_overrides(
            config,
            {"match": {"macaddress": "x"}, "mtu": 1500},
            protected=frozenset({"match"}),
            context="ctx",
        )
        assert config == {"mtu": 1500}
        assert mock_logger.warning.called

    def test_default_protected_applies_everything(self):
        config = {}
        _extractor()._apply_netplan_overrides(config, {"match": {}, "addresses": []})
        assert config == {"match": {}, "addresses": []}


# ---------------------------------------------------------------------------
# NetplanExtractor._register_vrf_membership
# ---------------------------------------------------------------------------


class TestRegisterVrfMembership:
    def test_id_not_in_assignments_is_noop(self):
        network_vrfs = {}
        _extractor()._register_vrf_membership(1, "eth0", {}, network_vrfs, "d1")
        assert network_vrfs == {}

    def test_creates_vrf_entry(self):
        network_vrfs = {}
        _extractor()._register_vrf_membership(
            1, "eth0", {1: ("vrf42", 42)}, network_vrfs, "d1"
        )
        assert network_vrfs == {"vrf42": {"table": 42, "interfaces": ["eth0"]}}

    def test_reuses_existing_entry(self):
        network_vrfs = {"vrf42": {"table": 42, "interfaces": ["eth0"]}}
        _extractor()._register_vrf_membership(
            2, "eth1", {2: ("vrf42", 42)}, network_vrfs, "d1"
        )
        assert network_vrfs["vrf42"]["interfaces"] == ["eth0", "eth1"]

    def test_duplicate_member_not_appended_twice(self):
        network_vrfs = {"vrf42": {"table": 42, "interfaces": ["eth0"]}}
        _extractor()._register_vrf_membership(
            1, "eth0", {1: ("vrf42", 42)}, network_vrfs, "d1"
        )
        assert network_vrfs["vrf42"]["interfaces"] == ["eth0"]


# ===========================================================================
# NetplanExtractor.extract -- per-interface-kind coverage.
#
# The LAG / bond kind is intentionally not re-tested here: the TestBond*
# classes above already exercise every documented bond branch.
# ===========================================================================


def _eth(id, label, *, mac="AA:BB:CC:00:00:01", tags=("managed-by-osism",), **kwargs):
    """A managed regular ethernet (type 1000base-t) with a MAC and label."""
    return make_interface(
        id=id,
        label=label,
        mac_address=mac,
        tags=tags,
        type=make_iface_type("1000base-t"),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Top-level guards & MTU
# ---------------------------------------------------------------------------


class TestExtractGuards:
    def test_no_api_returns_none(self):
        assert _extractor(api=None).extract(make_device(1, "d1")) is None

    def test_loader_raising_returns_none(self, monkeypatch):
        device = make_device(1, "d1")
        loader = BulkDataLoader(make_fake_api())
        monkeypatch.setattr(loader, "get_device_interfaces", _raise)
        assert _extractor(api=object(), loader=loader).extract(device) is None

    def test_no_interfaces_returns_none(self):
        assert _extractor(api=object()).extract(make_device(1, "d1")) is None

    def test_all_collections_empty_returns_none_no_write(self):
        device = make_device(1, "d1")
        iface = make_interface(id=1, tags=())  # no managed tag -> nothing collected
        loader = _loader_with(device, [iface])
        client = MagicMock()
        ex = _extractor(api=object(), netbox_client=client, loader=loader)
        assert ex.extract(device) is None
        client.update_device_custom_field.assert_not_called()


class TestSegmentDefaultMtu:
    def test_segment_default_mtu_overrides_default(self):
        device = make_device(1, "d1", config_context={"_segment_default_mtu": "9000"})
        iface = _eth(1, "eth1")  # mtu unset -> falls back to effective default
        loader = _loader_with(device, [iface])
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["network_ethernets"]["eth1"]["mtu"] == 9000

    def test_non_numeric_segment_mtu_warns_and_keeps_default(self, mock_logger):
        device = make_device(1, "d1", config_context={"_segment_default_mtu": "abc"})
        iface = _eth(1, "eth1")
        loader = _loader_with(device, [iface])
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["network_ethernets"]["eth1"]["mtu"] == 9100
        assert mock_logger.warning.called


# ---------------------------------------------------------------------------
# Regular ethernets
# ---------------------------------------------------------------------------


class TestRegularEthernets:
    def test_full_shape_with_lowercased_mac(self):
        device = make_device(1, "d1")
        iface = _eth(1, "leaf1", mac="AA:BB:CC:DD:EE:FF", mtu=9100)
        loader = _loader_with(device, [iface], {1: [make_ip("10.0.0.5/24")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["network_ethernets"]["leaf1"] == {
            "match": {"macaddress": "aa:bb:cc:dd:ee:ff"},
            "set-name": "leaf1",
            "mtu": 9100,
            "addresses": ["10.0.0.5/24"],
        }

    def test_interface_without_tags_is_skipped(self):
        device = make_device(1, "d1")
        loader = _loader_with(device, [_eth(1, "leaf1", tags=())])
        assert _extractor(api=object(), loader=loader).extract(device) is None

    def test_tagged_but_unmanaged_interface_is_skipped(self):
        # Tags present but none is managed-by-osism -> still skipped.
        device = make_device(1, "d1")
        loader = _loader_with(device, [_eth(1, "leaf1", tags=("production",))])
        assert _extractor(api=object(), loader=loader).extract(device) is None

    def test_mgmt_only_interface_is_skipped(self, mock_logger):
        device = make_device(1, "d1")
        loader = _loader_with(device, [_eth(1, "leaf1", mgmt_only=True)])
        assert _extractor(api=object(), loader=loader).extract(device) is None
        assert mock_logger.debug.called

    def test_missing_mac_is_skipped(self):
        device = make_device(1, "d1")
        loader = _loader_with(device, [_eth(1, "leaf1", mac=None)])
        assert _extractor(api=object(), loader=loader).extract(device) is None

    def test_missing_label_is_skipped(self):
        device = make_device(1, "d1")
        loader = _loader_with(device, [_eth(1, None, mac="AA:BB:CC:DD:EE:FF")])
        assert _extractor(api=object(), loader=loader).extract(device) is None

    def test_disabled_non_member_marks_activation_off(self):
        device = make_device(1, "d1")
        iface = _eth(1, "leaf1", enabled=False)
        loader = _loader_with(device, [iface], {1: [make_ip("10.0.0.5/24")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        # Only the rename identity and the down marker - no MTU / addresses.
        assert result["network_ethernets"]["leaf1"] == {
            "match": {"macaddress": "aa:bb:cc:00:00:01"},
            "set-name": "leaf1",
            "activation-mode": "off",
        }

    def test_leaf_interface_gets_link_local(self):
        device = make_device(1, "d1")
        ep = SimpleNamespace(device=make_device(2, "sw", role=make_tag("leaf")))
        iface = _eth(1, "leaf1", connected_endpoints=[ep])  # no IPs -> leaf
        loader = _loader_with(device, [iface])
        result = _extractor(api=object(), loader=loader).extract(device)
        cfg = result["network_ethernets"]["leaf1"]
        assert cfg["link-local"] == ["ipv6"]
        assert cfg["dhcp4"] is False
        assert cfg["dhcp6"] is False
        assert cfg["accept-ra"] is False

    def test_switch_connected_with_ips_is_not_a_leaf(self):
        device = make_device(1, "d1")
        ep = SimpleNamespace(device=make_device(2, "sw", role=make_tag("leaf")))
        iface = _eth(1, "leaf1", connected_endpoints=[ep])
        loader = _loader_with(device, [iface], {1: [make_ip("10.0.0.5/24")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        cfg = result["network_ethernets"]["leaf1"]
        assert "link-local" not in cfg
        assert "dhcp4" not in cfg

    def test_per_interface_netplan_params_override(self):
        device = make_device(1, "d1")
        iface = _eth(
            1,
            "leaf1",
            custom_fields={"netplan_parameters": {"mtu": 1500, "wakeonlan": True}},
        )
        loader = _loader_with(device, [iface])
        result = _extractor(api=object(), loader=loader).extract(device)
        cfg = result["network_ethernets"]["leaf1"]
        assert cfg["mtu"] == 1500
        assert cfg["wakeonlan"] is True


# ---------------------------------------------------------------------------
# loopback0
# ---------------------------------------------------------------------------


def _loopback0(**kwargs):
    return make_interface(
        id=10, name="loopback0", tags=("managed-by-osism",), mtu=9100, **kwargs
    )


class TestLoopback0:
    def test_addresses_and_mtu(self):
        device = make_device(1, "d1")
        loader = _loader_with(
            device, [_loopback0()], {10: [make_ip("192.168.45.123/32")]}
        )
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["network_dummy_devices"]["loopback0"] == {
            "addresses": ["192.168.45.123/32"],
            "mtu": 9100,
        }

    def test_metalbox_mode_appends_default_ipv6(self):
        device = make_device(1, "d1", role=make_tag("metalbox"))
        loader = _loader_with(
            device, [_loopback0()], {10: [make_ip("192.168.45.123/32")]}
        )
        result = _extractor(api=object(), loader=loader).extract(
            device, reconciler_mode="metalbox"
        )
        assert result["network_dummy_devices"]["loopback0"]["addresses"] == [
            "192.168.45.123/32",
            DEFAULT_METALBOX_IPV6,
        ]

    def test_custom_field_addresses_are_unioned(self):
        device = make_device(1, "d1")
        lo = _loopback0(
            custom_fields={
                "netplan_parameters": {
                    "addresses": ["192.168.45.123/32", "10.9.9.9/32"],
                    "mtu": 1500,
                }
            }
        )
        loader = _loader_with(device, [lo], {10: [make_ip("192.168.45.123/32")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        cfg = result["network_dummy_devices"]["loopback0"]
        # The collected address is not duplicated; other keys replace normally.
        assert cfg["addresses"] == ["192.168.45.123/32", "10.9.9.9/32"]
        assert cfg["mtu"] == 1500


# ---------------------------------------------------------------------------
# VLAN sub-interfaces
# ---------------------------------------------------------------------------


def _vlan(id, *, label, parent, vrf=None):
    return make_interface(
        id=id,
        label=label,
        tags=("managed-by-osism",),
        type=make_iface_type("virtual"),
        untagged_vlan=SimpleNamespace(vid=100),
        parent=parent,
        vrf=vrf,
    )


class TestVlans:
    def test_vlan_with_managed_parent(self):
        device = make_device(1, "d1")
        parent = make_interface(
            id=5, label="oob1", tags=("managed-by-osism",), mtu=9000
        )
        vlan = _vlan(6, label="vlan100", parent=parent)
        loader = _loader_with(device, [vlan], {6: [make_ip("172.16.10.5/20")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["network_vlans"]["vlan100"] == {
            "id": 100,
            "link": "oob1",
            "mtu": 9000,
            "addresses": ["172.16.10.5/20"],
        }

    def test_vlan_parent_without_tag_is_skipped(self):
        device = make_device(1, "d1")
        parent = make_interface(id=5, label="oob1", tags=(), mtu=9000)
        vlan = _vlan(6, label="vlan100", parent=parent)
        loader = _loader_with(device, [vlan], {6: [make_ip("172.16.10.5/20")]})
        assert _extractor(api=object(), loader=loader).extract(device) is None

    def test_vlan_with_vrf_is_registered(self):
        device = make_device(1, "d1")
        parent = make_interface(
            id=5, label="oob1", tags=("managed-by-osism",), mtu=9000
        )
        vlan = _vlan(6, label="vlan100", parent=parent, vrf=make_vrf("vrf42"))
        loader = _loader_with(device, [vlan], {6: [make_ip("172.16.10.5/20")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["network_vrfs"]["vrf42"]["interfaces"] == ["vlan100"]


# ---------------------------------------------------------------------------
# VXLAN tunnels
# ---------------------------------------------------------------------------


def _vxlan(id=20, *, vrf=None):
    return make_interface(
        id=id,
        name="vxlan42",
        label="vxlan42",
        tags=("managed-by-osism",),
        type=make_iface_type("virtual"),
        mtu=1500,
        vrf=vrf,
    )


class TestVxlans:
    def test_vxlan_full_shape(self):
        device = make_device(1, "d1")
        loader = _loader_with(
            device,
            [_loopback0(), _vxlan()],
            {10: [make_ip("192.168.45.123/32")], 20: [make_ip("10.170.64.2/24")]},
        )
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["network_tunnels"]["vxlan42"] == {
            "mode": "vxlan",
            "link": "loopback0",
            "id": 42,
            "accept-ra": False,
            "mac-learning": True,
            "port": 4789,
            "mtu": 1500,
            "local": "192.168.45.123",
            "addresses": ["10.170.64.2/24"],
        }

    def test_vxlan_without_loopback0_ipv4_omits_local(self, mock_logger):
        device = make_device(1, "d1")
        loader = _loader_with(device, [_vxlan()], {20: [make_ip("10.170.64.2/24")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert "local" not in result["network_tunnels"]["vxlan42"]
        assert mock_logger.warning.called

    def test_vxlan_with_vrf_is_registered(self):
        device = make_device(1, "d1")
        loader = _loader_with(
            device,
            [_loopback0(), _vxlan(vrf=make_vrf("vrf42"))],
            {10: [make_ip("192.168.45.123/32")], 20: [make_ip("10.170.64.2/24")]},
        )
        result = _extractor(api=object(), loader=loader).extract(device)
        assert "vxlan42" in result["network_vrfs"]["vrf42"]["interfaces"]


# ---------------------------------------------------------------------------
# VRF dummy interfaces
# ---------------------------------------------------------------------------


def _vrf_dummy(id=30, *, label, vrf):
    return make_interface(
        id=id,
        label=label,
        tags=("managed-by-osism",),
        type=make_iface_type("virtual"),
        vrf=vrf,
        mtu=9100,
    )


class TestVrfDummies:
    def test_table_from_vrf_name(self):
        device = make_device(1, "d1")
        dummy = _vrf_dummy(label="lo-vrf-a", vrf=make_vrf("vrf42"))
        loader = _loader_with(device, [dummy], {30: [make_ip("192.168.42.10/32")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["network_dummy_devices"]["lo-vrf-a"] == {
            "addresses": ["192.168.42.10/32"],
            "mtu": 9100,
        }
        assert result["network_vrfs"]["vrf42"] == {
            "table": 42,
            "interfaces": ["lo-vrf-a"],
        }

    def test_table_from_rd_with_colon(self):
        device = make_device(1, "d1")
        dummy = _vrf_dummy(
            label="lo-vrf-s", vrf=make_vrf("vrf-storage", rd="65000:1042")
        )
        loader = _loader_with(device, [dummy], {30: [make_ip("192.168.42.10/32")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["network_vrfs"]["vrf-storage"]["table"] == 1042

    def test_table_from_plain_rd(self):
        device = make_device(1, "d1")
        dummy = _vrf_dummy(label="lo-vrf-p", vrf=make_vrf("vrf-plain", rd="77"))
        loader = _loader_with(device, [dummy], {30: [make_ip("192.168.42.10/32")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert result["network_vrfs"]["vrf-plain"]["table"] == 77

    def test_unresolvable_table_warns_and_excludes_from_vrfs(self, mock_logger):
        device = make_device(1, "d1")
        dummy = _vrf_dummy(label="lo-vrf-x", vrf=make_vrf("vrf-none", rd=None))
        loader = _loader_with(device, [dummy], {30: [make_ip("192.168.42.10/32")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        # The dummy device is still emitted, but no VRF entry is created for it.
        assert "lo-vrf-x" in result["network_dummy_devices"]
        assert "network_vrfs" not in result
        assert mock_logger.warning.called

    def test_unparseable_rd_warns_and_excludes_from_vrfs(self, mock_logger):
        device = make_device(1, "d1")
        dummy = _vrf_dummy(label="lo-vrf-b", vrf=make_vrf("vrf-bad", rd="abc:def"))
        loader = _loader_with(device, [dummy], {30: [make_ip("192.168.42.10/32")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert "lo-vrf-b" in result["network_dummy_devices"]
        assert "network_vrfs" not in result
        assert mock_logger.warning.called


# ---------------------------------------------------------------------------
# Metalbox dummy, result assembly & caching
# ---------------------------------------------------------------------------


class TestResultAssemblyAndCaching:
    def test_metalbox_dummy_device(self):
        device = make_device(1, "d1", role=make_tag("metalbox"))
        loader = _loader_with(
            device, [_loopback0()], {10: [make_ip("192.168.45.123/32")]}
        )
        result = _extractor(api=object(), loader=loader).extract(
            device, reconciler_mode="metalbox"
        )
        assert result["network_dummy_devices"]["metalbox"] == {
            "addresses": ["192.168.42.10/24"]
        }

    def test_only_nonempty_collections_are_present(self):
        device = make_device(1, "d1")
        iface = _eth(1, "leaf1", mtu=9100)
        loader = _loader_with(device, [iface], {1: [make_ip("10.0.0.5/24")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        assert set(result.keys()) == {"network_ethernets"}

    def test_config_context_overrides_are_deep_merged(self, mock_logger):
        device = make_device(
            1,
            "d1",
            config_context={
                "netplan_parameters": {
                    "network_ethernets": {"leaf1": {"mtu": 1500}},
                    "extra": "x",
                }
            },
        )
        iface = _eth(1, "leaf1", mtu=9100)
        loader = _loader_with(device, [iface], {1: [make_ip("10.0.0.5/24")]})
        result = _extractor(api=object(), loader=loader).extract(device)
        leaf1 = result["network_ethernets"]["leaf1"]
        assert leaf1["mtu"] == 1500  # override wins
        assert leaf1["addresses"] == ["10.0.0.5/24"]  # untouched auto key survives
        assert result["extra"] == "x"  # new key from config_context
        assert mock_logger.info.called

    def test_config_context_only_default_is_emitted_and_written(self):
        # An interface exists but auto-generates nothing (no managed tag), yet
        # config_context carries a netplan_parameters default. Since
        # ConfigContextExtractor strips netplan_parameters from the generic
        # config-context output, this extractor is its only emission surface and
        # must still emit (and cache) it rather than dropping it via an emptiness
        # check that runs before the merge.
        device = make_device(
            1,
            "d1",
            config_context={
                "netplan_parameters": {"network_ethernets": {"x": {"mtu": 1500}}}
            },
        )
        iface = make_interface(id=1, tags=())  # nothing auto-collected
        loader = _loader_with(device, [iface])
        client = MagicMock()
        client.update_device_custom_field.return_value = True
        result = _extractor(api=object(), netbox_client=client, loader=loader).extract(
            device
        )
        assert result == {"network_ethernets": {"x": {"mtu": 1500}}}
        client.update_device_custom_field.assert_called_once_with(
            device, "netplan_parameters", result
        )

    def test_no_interfaces_with_config_context_default_is_emitted(self):
        # Even with zero interfaces an empty list is no longer an early exit, so
        # a config_context netplan default is still emitted (symmetric with the
        # FRR extractor).
        device = make_device(
            1,
            "d1",
            config_context={
                "netplan_parameters": {"network_ethernets": {"x": {"mtu": 1500}}}
            },
        )
        result = _extractor(api=object()).extract(device)
        assert result == {"network_ethernets": {"x": {"mtu": 1500}}}

    def test_netbox_client_write_called_once(self):
        device = make_device(1, "d1")
        iface = _eth(1, "leaf1", mtu=9100)
        loader = _loader_with(device, [iface], {1: [make_ip("10.0.0.5/24")]})
        client = MagicMock()
        client.update_device_custom_field.return_value = True
        result = _extractor(api=object(), netbox_client=client, loader=loader).extract(
            device
        )
        client.update_device_custom_field.assert_called_once_with(
            device, "netplan_parameters", result
        )

    def test_netbox_client_falsy_return_warns(self, mock_logger):
        device = make_device(1, "d1")
        iface = _eth(1, "leaf1", mtu=9100)
        loader = _loader_with(device, [iface], {1: [make_ip("10.0.0.5/24")]})
        client = MagicMock()
        client.update_device_custom_field.return_value = False
        _extractor(api=object(), netbox_client=client, loader=loader).extract(device)
        assert mock_logger.warning.called

    def test_netbox_client_none_no_write(self):
        device = make_device(1, "d1")
        iface = _eth(1, "leaf1", mtu=9100)
        loader = _loader_with(device, [iface], {1: [make_ip("10.0.0.5/24")]})
        result = _extractor(api=object(), netbox_client=None, loader=loader).extract(
            device
        )
        assert "network_ethernets" in result


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
