# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/extractors/primary_ip_extractor.py.

Pure-logic tests: the extractor only reads ``primary_ip4`` / ``primary_ip6`` /
``primary_ip`` off a device and strips the subnet mask. The three IP attributes
are attached inline because ``make_device`` does not model them.
"""

import pytest

from extractors.primary_ip_extractor import PrimaryIPExtractor

from .conftest import make_device, make_ip


def _device_with_ips(*, ip4=None, ip6=None, ip=None):
    """Build a device exposing all three primary-IP attributes."""
    device = make_device(1, "node1")
    device.primary_ip4 = ip4
    device.primary_ip6 = ip6
    device.primary_ip = ip
    return device


class TestExtract:
    def test_primary_ip4_strips_mask_and_ignores_ipv6(self):
        device = _device_with_ips(
            ip4=make_ip("10.0.0.5/24"),
            ip6=make_ip("2001:db8::5/64"),
        )
        assert PrimaryIPExtractor().extract(device) == "10.0.0.5"

    def test_falls_back_to_ipv6_when_ipv4_absent(self):
        device = _device_with_ips(ip6=make_ip("2001:db8::5/64"))
        assert PrimaryIPExtractor().extract(device) == "2001:db8::5"

    def test_legacy_primary_ip_fallback(self):
        device = _device_with_ips(ip=make_ip("172.16.0.9/16"))
        assert PrimaryIPExtractor().extract(device) == "172.16.0.9"

    def test_returns_none_when_no_ip_set(self):
        device = _device_with_ips()
        assert PrimaryIPExtractor().extract(device) is None

    def test_address_without_mask_returned_unchanged(self):
        device = _device_with_ips(ip4=make_ip("10.0.0.5"))
        assert PrimaryIPExtractor().extract(device) == "10.0.0.5"

    def test_ipv4_wins_when_all_three_set(self):
        device = _device_with_ips(
            ip4=make_ip("10.0.0.5/24"),
            ip6=make_ip("2001:db8::5/64"),
            ip=make_ip("172.16.0.9/16"),
        )
        assert PrimaryIPExtractor().extract(device) == "10.0.0.5"

    def test_extra_kwargs_are_ignored(self):
        device = _device_with_ips(ip4=make_ip("10.0.0.5/24"))
        assert PrimaryIPExtractor().extract(device, unused="x") == "10.0.0.5"


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
