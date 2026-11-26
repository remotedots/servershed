"""Inventory model: loads and validates inventory.yaml."""
from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, model_validator


class Kind(str, Enum):
    vps = "vps"
    shared = "shared"
    external = "external"


class Asset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    kind: Kind
    ssh: str | None = None          # ~/.ssh/config Host alias
    probe: bool = True
    provider: str | None = None
    docroot: str | list[str] | None = None   # one web root, or a list (several sites per account)
    notes: str | None = None
    sites: list[str] = []

    @model_validator(mode="after")
    def _check(self) -> "Asset":
        if self.kind is Kind.external:
            self.probe = False
        if self.probe and not self.ssh:
            raise ValueError(f"{self.name}: probe is on but no 'ssh' alias given")
        return self

    @property
    def docroots(self) -> list[str]:
        if self.docroot is None:
            return []
        return [self.docroot] if isinstance(self.docroot, str) else list(self.docroot)

    @property
    def probes(self) -> bool:
        return self.probe and self.ssh is not None


class Client(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    assets: list[Asset] = []


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    clients: list[Client] = []

    def assets(self) -> list[tuple[Client, Asset]]:
        return [(c, a) for c in self.clients for a in c.assets]

    @model_validator(mode="after")
    def _unique(self) -> "Inventory":
        seen: set[str] = set()
        for _, a in self.assets():
            if a.name in seen:
                raise ValueError(f"duplicate asset name: {a.name}")
            seen.add(a.name)
        return self


def load(path: str | Path) -> Inventory:
    data = yaml.safe_load(Path(path).read_text()) or {}
    return Inventory.model_validate(data)
