# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/connection.py.

``ConnectionManager`` wraps ``pynetbox.api`` with retry and optional SSL-ignore
handling. The collaborators are monkeypatched in the *module under test's*
namespace (flat imports): ``connection.pynetbox.api``, ``connection.time.sleep``
and ``connection.requests`` members. ``time.sleep`` is patched in every
``connect()`` test so retries never actually wait. The config is a plain
``SimpleNamespace`` stand-in -- the real ``Config`` is intentionally not used.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import connection
from connection import ConnectionManager
from exceptions import NetBoxConnectionError


def _config(*, ignore_ssl_errors=False, retry_attempts=3, retry_delay=1):
    """A minimal Config stand-in exposing only the attributes connect() reads."""
    return SimpleNamespace(
        netbox_url="https://netbox.example.com",
        netbox_token="token-123",
        ignore_ssl_errors=ignore_ssl_errors,
        retry_attempts=retry_attempts,
        retry_delay=retry_delay,
    )


@pytest.fixture
def patched(monkeypatch):
    """Patch connect()'s collaborators in the connection module namespace.

    ``pynetbox.api`` becomes a factory returning ``fake_api``; ``time.sleep``
    becomes a no-op spy so retries never wait.
    """
    fake_api = MagicMock(name="netbox_api")
    api_factory = MagicMock(name="pynetbox.api", return_value=fake_api)
    sleep = MagicMock(name="time.sleep")
    monkeypatch.setattr(connection.pynetbox, "api", api_factory)
    monkeypatch.setattr(connection.time, "sleep", sleep)
    return SimpleNamespace(api_factory=api_factory, fake_api=fake_api, sleep=sleep)


@pytest.fixture
def disable_warnings(monkeypatch):
    """Spy on requests.packages.urllib3.disable_warnings."""
    spy = MagicMock(name="disable_warnings")
    monkeypatch.setattr(connection.requests.packages.urllib3, "disable_warnings", spy)
    return spy


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestInit:
    def test_stores_config_and_initializes_state(self):
        config = _config()
        manager = ConnectionManager(config)
        assert manager.config is config
        assert manager.api is None
        assert manager._session is None


# ---------------------------------------------------------------------------
# connect
# ---------------------------------------------------------------------------


class TestConnect:
    def test_success_on_first_attempt(self, patched):
        patched.fake_api.dcim.sites.count.return_value = 5
        config = _config()
        manager = ConnectionManager(config)
        result = manager.connect()
        assert result is patched.fake_api
        patched.api_factory.assert_called_once_with(
            config.netbox_url, config.netbox_token
        )
        patched.sleep.assert_not_called()

    def test_ignore_ssl_errors_configures_session(self, patched, disable_warnings):
        patched.fake_api.dcim.sites.count.return_value = 5
        manager = ConnectionManager(_config(ignore_ssl_errors=True))
        manager.connect()
        disable_warnings.assert_called_once()
        assert isinstance(manager.api.http_session, connection.requests.Session)
        assert manager.api.http_session.verify is False

    def test_no_ssl_branch_leaves_session_untouched(self, patched, disable_warnings):
        patched.fake_api.dcim.sites.count.return_value = 5
        manager = ConnectionManager(_config(ignore_ssl_errors=False))
        manager.connect()
        disable_warnings.assert_not_called()
        assert manager._session is None

    def test_retry_then_success_sleeps_once(self, patched):
        patched.fake_api.dcim.sites.count.side_effect = [Exception("boom"), 5]
        config = _config()
        manager = ConnectionManager(config)
        result = manager.connect()
        assert result is patched.fake_api
        patched.sleep.assert_called_once_with(config.retry_delay)

    def test_retry_exhaustion_raises_with_cause(self, patched):
        boom = RuntimeError("boom")
        patched.fake_api.dcim.sites.count.side_effect = boom
        manager = ConnectionManager(_config(retry_attempts=3))
        with pytest.raises(NetBoxConnectionError) as exc_info:
            manager.connect()
        assert exc_info.value.__cause__ is boom
        assert patched.sleep.call_count == 2  # retry_attempts - 1

    def test_pynetbox_api_raising_uses_retry_path(self, patched):
        boom = RuntimeError("api down")
        patched.api_factory.side_effect = boom
        manager = ConnectionManager(_config(retry_attempts=3))
        with pytest.raises(NetBoxConnectionError) as exc_info:
            manager.connect()
        assert exc_info.value.__cause__ is boom
        assert patched.sleep.call_count == 2

    def test_ignore_ssl_errors_reruns_per_retry_and_leaks_old_session(
        self, patched, disable_warnings, monkeypatch
    ):
        """Characterize the SSL-ignore x retry intersection.

        With ``ignore_ssl_errors=True`` and a failing probe, ``connect()`` runs
        ``_configure_ssl_ignore()`` on every attempt and rebinds
        ``self._session = requests.Session()`` without closing the previous
        session -- so each retry leaks the prior session (and its connection
        pool) until GC reclaims it. This test pins that behavior; a future fix
        that closes the old session before rebinding must update it
        deliberately.
        """
        sessions = []

        def session_factory():
            session = MagicMock(name=f"session-{len(sessions)}")
            sessions.append(session)
            return session

        monkeypatch.setattr(connection.requests, "Session", session_factory)
        # First probe fails, second succeeds -> two attempts, two sessions.
        patched.fake_api.dcim.sites.count.side_effect = [Exception("boom"), 5]
        manager = ConnectionManager(_config(ignore_ssl_errors=True))

        manager.connect()

        assert len(sessions) == 2  # one fresh session per attempt
        assert disable_warnings.call_count == 2
        sessions[0].close.assert_not_called()  # the leak: never closed
        assert manager._session is sessions[1]


# ---------------------------------------------------------------------------
# _configure_ssl_ignore
# ---------------------------------------------------------------------------


class TestConfigureSslIgnore:
    def test_with_api_attaches_session(self, disable_warnings):
        manager = ConnectionManager(_config())
        manager.api = MagicMock()
        manager._configure_ssl_ignore()
        disable_warnings.assert_called_once()
        assert manager._session.verify is False
        assert manager.api.http_session is manager._session

    def test_with_api_none_creates_session_but_does_not_attach(self, disable_warnings):
        manager = ConnectionManager(_config())
        manager.api = None
        manager._configure_ssl_ignore()  # must not raise (the `if self.api` guard)
        disable_warnings.assert_called_once()
        assert isinstance(manager._session, connection.requests.Session)
        assert manager._session.verify is False
        assert manager.api is None


# ---------------------------------------------------------------------------
# disconnect
# ---------------------------------------------------------------------------


class TestDisconnect:
    def test_closes_session_and_clears_state(self):
        manager = ConnectionManager(_config())
        session = MagicMock()
        manager._session = session
        manager.api = MagicMock()
        manager.disconnect()
        session.close.assert_called_once()
        assert manager._session is None
        assert manager.api is None

    def test_is_idempotent(self):
        manager = ConnectionManager(_config())
        manager._session = MagicMock()
        manager.api = MagicMock()
        manager.disconnect()
        manager.disconnect()  # second call hits the `if self._session` guard
        assert manager._session is None
        assert manager.api is None

    def test_without_prior_connect_does_not_raise(self):
        manager = ConnectionManager(_config())
        manager.disconnect()  # _session and api are already None
        assert manager._session is None
        assert manager.api is None


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
