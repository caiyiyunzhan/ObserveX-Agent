from dataclasses import dataclass, field


@dataclass
class TokenCounter:
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.total_prompt_tokens + self.total_completion_tokens

    def record(self, prompt_tokens: int, completion_tokens: int) -> None:
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        print(
            f"[TokenUsage] prompt={prompt_tokens} "
            f"completion={completion_tokens} "
            f"cumulative_total={self.total_tokens}"
        )

    def summary(self) -> dict:
        return {
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_tokens,
        }


_global_counter = TokenCounter()


def get_token_counter() -> TokenCounter:
    return _global_counter
