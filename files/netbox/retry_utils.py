# SPDX-License-Identifier: Apache-2.0

"""Retry utilities for handling transient API failures."""

import time
from functools import wraps
from typing import Callable

from loguru import logger


def retry_on_api_error(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
):
    """Decorator that retries a function on API errors with exponential backoff.

    Retries on:
    - HTTP 500, 502, 503, 504 (server errors)
    - HTTP 429 (rate limit)
    - Timeout and connection errors

    Does not retry on:
    - HTTP 4xx client errors (except 429)
    - Logic/validation errors

    Args:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay between retries (seconds)
        backoff_factor: Multiplier for exponential backoff

    Returns:
        Decorated function with retry logic
    """

    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e

                    if attempt < max_retries and _is_retryable_error(e):
                        logger.warning(
                            f"{func.__name__}: Attempt {attempt + 1}/{max_retries + 1} failed: {e}. "
                            f"Retrying in {delay:.1f}s..."
                        )
                        time.sleep(delay)
                        delay *= backoff_factor
                    elif not _is_retryable_error(e):
                        # Non-retryable error, raise immediately
                        logger.error(f"{func.__name__}: Non-retryable error: {e}")
                        raise
                    else:
                        # Max retries exhausted
                        logger.error(
                            f"{func.__name__}: All {max_retries + 1} attempts failed: {e}"
                        )
                        raise

            raise last_exception

        return wrapper

    return decorator


def _is_retryable_error(error: Exception) -> bool:
    """Determine if an error should be retried.

    Args:
        error: Exception that occurred

    Returns:
        True if error is retryable, False otherwise
    """
    error_str = str(error).lower()

    # Retryable HTTP status codes
    retryable_codes = ["500", "502", "503", "504", "429"]
    if any(code in error_str for code in retryable_codes):
        return True

    # Retryable error patterns
    retryable_patterns = ["timeout", "connection", "network", "refused"]
    if any(pattern in error_str for pattern in retryable_patterns):
        return True

    return False
