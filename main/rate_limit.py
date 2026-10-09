"""Simple IP-based rate limiting using Django cache (locmem by default)."""

import functools
import logging

from django.core.cache import cache
from django.http import JsonResponse

logger = logging.getLogger(__name__)


def rate_limit(max_requests: int = 10, window: int = 60, key_prefix: str = "rl"):
    """
    Decorator for class-based views (post/get methods).

    Limits requests per client IP.
    Default: 10 requests per 60 seconds.
    """

    def decorator(view_method):
        @functools.wraps(view_method)
        def wrapper(self, request, *args, **kwargs):
            ip = _client_ip(request)
            cache_key = f"{key_prefix}:{view_method.__qualname__}:{ip}"

            count = cache.get(cache_key, 0)
            if count >= max_requests:
                logger.warning("Rate limit exceeded for %s on %s", ip, view_method.__qualname__)
                return JsonResponse(
                    {"error": "Слишком много запросов. Подождите немного и попробуйте снова."},
                    status=429,
                )

            cache.set(cache_key, count + 1, timeout=window)
            return view_method(self, request, *args, **kwargs)

        return wrapper

    return decorator


def _client_ip(request) -> str:
    x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")
