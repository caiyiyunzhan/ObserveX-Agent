from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from kcrash.exceptions import AuthenticationError, RateLimitExceededError


@dataclass
class APIKey:
    key_id: str
    key_hash: str
    name: str
    scopes: list[str]
    created_at: float
    expires_at: float | None = None
    rate_limit: int = 100
    enabled: bool = True


@dataclass
class RateLimitBucket:
    tokens: float
    last_refill: float
    capacity: int
    refill_rate: float


class APIKeyStore:
    def __init__(self) -> None:
        self._keys: dict[str, APIKey] = {}
        self._buckets: dict[str, RateLimitBucket] = {}

    @staticmethod
    def generate_key() -> tuple[str, str]:
        raw_key = f"kcrash-{secrets.token_hex(32)}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        return raw_key, key_hash

    def register_key(
        self,
        name: str,
        scopes: list[str] | None = None,
        rate_limit: int = 100,
        ttl_days: int = 90,
    ) -> tuple[str, APIKey]:
        raw_key, key_hash = self.generate_key()
        key_id = secrets.token_hex(8)
        now = time.time()

        api_key = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            name=name,
            scopes=scopes or ["analyze"],
            created_at=now,
            expires_at=now + ttl_days * 86400,
            rate_limit=rate_limit,
        )

        self._keys[key_id] = api_key
        self._buckets[key_id] = RateLimitBucket(
            tokens=float(rate_limit),
            last_refill=now,
            capacity=rate_limit,
            refill_rate=rate_limit / 60.0,
        )

        return raw_key, api_key

    def authenticate(self, raw_key: str) -> APIKey:
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        now = time.time()

        for key_id, api_key in self._keys.items():
            if api_key.key_hash == key_hash:
                if not api_key.enabled:
                    raise AuthenticationError("API key is disabled")
                if api_key.expires_at and now > api_key.expires_at:
                    raise AuthenticationError("API key has expired")
                return api_key

        raise AuthenticationError("Invalid API key")

    def check_rate_limit(self, key_id: str) -> None:
        bucket = self._buckets.get(key_id)
        if bucket is None:
            return

        now = time.time()
        elapsed = now - bucket.last_refill
        bucket.tokens = min(bucket.capacity, bucket.tokens + elapsed * bucket.refill_rate)
        bucket.last_refill = now

        if bucket.tokens < 1:
            wait_time = (1 - bucket.tokens) / bucket.refill_rate
            raise RateLimitExceededError(retry_after=int(wait_time) + 1)

        bucket.tokens -= 1

    def check_scope(self, api_key: APIKey, required_scope: str) -> None:
        if required_scope not in api_key.scopes and "*" not in api_key.scopes:
            raise AuthenticationError(
                f"Insufficient scope: '{required_scope}' not in {api_key.scopes}"
            )

    def disable_key(self, key_id: str) -> None:
        if key_id in self._keys:
            self._keys[key_id].enabled = False

    def list_keys(self) -> list[dict[str, Any]]:
        return [
            {
                "key_id": k.key_id,
                "name": k.name,
                "scopes": k.scopes,
                "enabled": k.enabled,
                "rate_limit": k.rate_limit,
                "created_at": k.created_at,
                "expires_at": k.expires_at,
            }
            for k in self._keys.values()
        ]
