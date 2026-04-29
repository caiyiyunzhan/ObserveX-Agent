from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from openai import OpenAI
from openai.types.chat import ChatCompletion

from kcrash.utils.token_counter import get_token_counter


@dataclass
class LLMCallResult:
    content: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    model: str
    retry_count: int = 0


@dataclass
class RateLimiter:
    calls_per_minute: int = 60
    _timestamps: list[float] = field(default_factory=list)

    def acquire(self) -> None:
        now = time.time()
        window = 60.0
        self._timestamps = [t for t in self._timestamps if now - t < window]
        if len(self._timestamps) >= self.calls_per_minute:
            sleep_time = window - (now - self._timestamps[0]) + 0.1
            if sleep_time > 0:
                time.sleep(sleep_time)
        self._timestamps.append(time.time())


class LLMClient:
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4-turbo",
        base_url: str | None = None,
        max_retries: int = 3,
        retry_delay: float = 2.0,
        timeout: float = 120.0,
        rate_limit_rpm: int = 60,
    ) -> None:
        self._model = model
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._timeout = timeout
        self._limiter = RateLimiter(calls_per_minute=rate_limit_rpm)

        client_kwargs: dict[str, Any] = {
            "api_key": api_key,
            "timeout": timeout,
        }
        if base_url:
            client_kwargs["base_url"] = base_url
        self._client = OpenAI(**client_kwargs)

    @property
    def model(self) -> str:
        return self._model

    def chat(
        self,
        system: str,
        user: str,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        json_mode: bool = False,
        tools: list[dict] | None = None,
    ) -> LLMCallResult:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        return self._call(messages, max_tokens, temperature, json_mode, tools)

    def chat_messages(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.1,
        json_mode: bool = False,
    ) -> LLMCallResult:
        return self._call(messages, max_tokens, temperature, json_mode, None)

    def _call(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float,
        json_mode: bool,
        tools: list[dict] | None,
    ) -> LLMCallResult:
        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                self._limiter.acquire()
                start = time.time()

                kwargs: dict[str, Any] = {
                    "model": self._model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                }
                if json_mode:
                    kwargs["response_format"] = {"type": "json_object"}
                if tools:
                    kwargs["tools"] = tools

                response: ChatCompletion = self._client.chat.completions.create(
                    **kwargs
                )
                elapsed_ms = (time.time() - start) * 1000

                usage = response.usage
                counter = get_token_counter()
                counter.record(
                    prompt_tokens=usage.prompt_tokens,
                    completion_tokens=usage.completion_tokens,
                )

                content = response.choices[0].message.content or ""

                return LLMCallResult(
                    content=content,
                    prompt_tokens=usage.prompt_tokens,
                    completion_tokens=usage.completion_tokens,
                    latency_ms=elapsed_ms,
                    model=self._model,
                    retry_count=attempt,
                )

            except Exception as exc:
                last_error = exc
                if attempt < self._max_retries:
                    delay = self._retry_delay * (2 ** attempt)
                    print(
                        f"[LLMClient] Attempt {attempt + 1} failed: {exc}. "
                        f"Retrying in {delay:.1f}s..."
                    )
                    time.sleep(delay)

        raise RuntimeError(
            f"LLM call failed after {self._max_retries + 1} attempts: {last_error}"
        )

    def parse_json(self, result: LLMCallResult) -> dict[str, Any]:
        text = result.content.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            if lines and lines[0].startswith("json"):
                lines[0] = lines[0][4:]
            text = "\n".join(lines)
        return json.loads(text)
