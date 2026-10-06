from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from src.providers.base import ProviderConnectionError, ProviderResponseError


class JsonHttpTransport:
    """Small injectable JSON transport; it never logs headers or credentials."""

    def request(
        self,
        url: str,
        *,
        method: str = "POST",
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise ProviderConnectionError(f"Provider HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProviderConnectionError(f"Provider connection failed: {exc}") from exc
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProviderResponseError("Provider returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise ProviderResponseError("Provider response must be a JSON object")
        return value

