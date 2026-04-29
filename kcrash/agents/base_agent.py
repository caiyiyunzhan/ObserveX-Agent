from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class Argument(BaseModel):
    agent_name: str = ""
    claim: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidences: list[str] = Field(default_factory=list)


class BaseAgent(ABC):
    name: str

    @abstractmethod
    def initial_argument(self, context: dict[str, Any]) -> Argument:
        raise NotImplementedError

    @abstractmethod
    def rebut(
        self, opponent_arguments: list[Argument], context: dict[str, Any]
    ) -> Argument:
        raise NotImplementedError
