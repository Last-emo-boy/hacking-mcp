"""Shared types for generated MCP tool adapters."""

from dataclasses import dataclass
from typing import Annotated, Any

from pydantic import Field


@dataclass(frozen=True)
class AdapterParameterSpec:
    """A generated MCP argument for a per-tool adapter."""

    name: str
    typ: type
    default: Any
    description: str

    def annotation(self) -> Any:
        return Annotated[self.typ, Field(description=self.description)]
