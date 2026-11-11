"""Scenario file models (plan Task 13). Each scenario carries its expected outcome: the lab ground truth."""

from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class _Step(BaseModel):
    model_config = ConfigDict(extra="forbid")
    delay_s: float = 0


class Exec(_Step):
    type: Literal["exec"]
    host: str
    user: str = "root"
    cmd: str


class Authn(_Step):
    type: Literal["authn"]
    user: str
    password_ok: bool
    source_ip: str
    country: str
    repeat: int = 1


class MfaPush(_Step):
    type: Literal["mfa_push"]
    user: str
    result: Literal["approved", "denied", "timeout"]
    repeat: int = 1


class CloudCall(_Step):
    type: Literal["cloud_call"]
    key_id: str
    action: Literal["ListBuckets", "GetObject", "CreateUser", "AttachPolicy"]
    source_ip: str


Step = Annotated[Exec | Authn | MfaPush | CloudCall, Field(discriminator="type")]


class Expected(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["true_positive", "benign", "injection_attempt"]
    action: str | None
    also: list[str] = Field(default_factory=list)
    entities: list[str]
    sources: list[str]
    techniques: list[str] = Field(default_factory=list)


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    description: str
    steps: list[Step]
    expected: Expected


def load(path: Path) -> dict[str, Scenario]:
    data = yaml.safe_load(Path(path).read_text())
    return {s["id"]: Scenario.model_validate(s) for s in data["scenarios"]}
