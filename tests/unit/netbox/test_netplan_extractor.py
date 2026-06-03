# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the LAG / bond (port channel) handling in NetplanExtractor.

The extractor reads device interfaces through a ``BulkDataLoader`` and writes
the generated parameters back through a ``NetBoxClient``. Both collaborators are
replaced by thin stubs here; only the attributes the extractor actually reads
off interface / IP objects are modelled (mirroring the SONiC NetBox modelling:
a LAG is an interface of ``type == "lag"`` and members carry a ``lag`` back-ref).
"""

from types import SimpleNamespace

from extractors.netplan_extractor import NetplanExtractor


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
