"""Wire formats for sentrix-edr: what sensors send, what the feed returns."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class HookEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    t: float
    pid: int
    ppid: int
    uid: int
    user: str | None = None
    comm: str
    kind: Literal["exec", "open", "connect", "file_access_unattributed", "proc"]
    argv: list[str] | None = None
    path: str | None = None
    mode: Literal["read", "write"] | None = None
    ip: str | None = None
    port: int | None = None
    truncated: bool = False


class LineageEntry(BaseModel):
    cmdline: str
    user: str
    pid: int


class DetectionProcess(BaseModel):
    cmdline: str
    user: str
    pid: int
    parent_cmdline: str | None = None
    lineage: list[LineageEntry] = Field(default_factory=list, max_length=6)


class DetectionNet(BaseModel):
    ip: str
    port: int


class DetectionFile(BaseModel):
    path: str
    op: Literal["read", "write"]


class Detection(BaseModel):
    name: str
    technique: str | None = None
    severity: int = Field(ge=0, le=100)
    t: float
    process: DetectionProcess | None = None
    net: DetectionNet | None = None
    file: DetectionFile | None = None


class TelemetryBatch(BaseModel):
    host: str
    events: list[HookEvent] = Field(default_factory=list)
    detections: list[Detection] = Field(default_factory=list)
