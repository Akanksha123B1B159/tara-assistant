"""Validated structures emitted by deterministic asset and surface analysis."""
from pydantic import BaseModel, ConfigDict, Field


class AssetCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    tag: str
    type: str
    interface: str
    properties: str
    description: str
    owner: str
    origin: str
    citations: list[str] = Field(min_length=1)


class TrustBoundary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    boundary_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    citations: list[str] = Field(min_length=1)


class AttackSurfaceCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interface: str
    interface_name: str
    entry_point: str = Field(min_length=1)
    vector: str = Field(min_length=1)
    exposure: str
    asset_ids: list[str]
    asset_names: list[str]
    trust_boundary: str
    citations: list[str]
    derivation: str
    evidence_status: str
    assumptions: list[str] = Field(min_length=1)
    warning: str | None = None
