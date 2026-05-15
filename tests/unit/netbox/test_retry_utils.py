# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/retry_utils.py.

``time.sleep`` is patched out so the backoff schedule can be asserted without
the suite ever actually sleeping.
"""

import pytest

from retry_utils import _is_retryable_error, retry_on_api_error


@pytest.fixture
def sleep_calls(monkeypatch):
    """Patch ``time.sleep`` and capture the delays it is called with."""
    calls = []
    monkeypatch.setattr("time.sleep", calls.append)
    return calls


class TestRetryOnApiError:
    def test_success_on_first_try(self, sleep_calls):
        calls = []

        @retry_on_api_error()
        def func():
            calls.append(1)
            return "ok"

        assert func() == "ok"
        assert len(calls) == 1
        assert sleep_calls == []

    def test_retryable_error_then_success(self, sleep_calls):
        attempts = []

        @retry_on_api_error(max_retries=3)
        def func():
            attempts.append(1)
            if len(attempts) < 3:
                raise Exception("503 service unavailable")
            return "recovered"

        assert func() == "recovered"
        assert len(attempts) == 3

    def test_retryable_error_every_time_reraises_last(self, sleep_calls):
        attempts = []

        @retry_on_api_error(max_retries=3)
        def func():
            attempts.append(1)
            raise Exception("503 service unavailable")

        with pytest.raises(Exception, match="503 service unavailable"):
            func()
        assert len(attempts) == 4  # max_retries + 1 total attempts

    def test_non_retryable_error_raised_immediately(self, sleep_calls):
        attempts = []

        @retry_on_api_error(max_retries=3)
        def func():
            attempts.append(1)
            raise ValueError("bad input")

        with pytest.raises(ValueError, match="bad input"):
            func()
        assert len(attempts) == 1  # no retries
        assert sleep_calls == []

    def test_exponential_backoff_delays(self, sleep_calls):
        @retry_on_api_error(max_retries=3, initial_delay=1.0, backoff_factor=2.0)
        def func():
            raise Exception("503 service unavailable")

        with pytest.raises(Exception, match="503"):
            func()
        # initial_delay, then multiplied by backoff_factor before each retry
        assert sleep_calls == [1.0, 2.0, 4.0]

    def test_wraps_preserves_function_name(self):
        @retry_on_api_error()
        def my_named_function():
            return None

        assert my_named_function.__name__ == "my_named_function"


class TestIsRetryableError:
    @pytest.mark.parametrize("code", ["500", "502", "503", "504", "429"])
    def test_retryable_http_status_codes(self, code):
        assert _is_retryable_error(Exception(f"server returned {code}")) is True

    @pytest.mark.parametrize(
        "message",
        ["TIMEOUT occurred", "Connection lost", "NETWORK error", "Refused"],
    )
    def test_retryable_patterns_are_case_insensitive(self, message):
        # the function lowercases the message before matching
        assert _is_retryable_error(Exception(message)) is True

    @pytest.mark.parametrize(
        "message",
        ["400 bad request", "401 unauthorized", "404 not found"],
    )
    def test_non_429_client_errors_are_not_retryable(self, message):
        assert _is_retryable_error(Exception(message)) is False

    def test_unrelated_message_is_not_retryable(self):
        assert _is_retryable_error(Exception("validation failed")) is False

    def test_substring_match_is_greedy(self):
        # The check is plain substring matching, so "500" inside "500abc"
        # still counts as retryable. This is a known limitation, asserted
        # here so a future tightening of the matching is a deliberate change.
        assert _is_retryable_error(Exception("500abc")) is True
