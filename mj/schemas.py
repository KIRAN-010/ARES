from enum import Enum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator
import ipaddress
import math
import re


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TargetInput(StrictModel):
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["web", "network", "host", "vm"] = "web"
    address: str = "127.0.0.1"
    ports: list[int] = Field(default_factory=lambda: [8091], min_length=1, max_length=16)
    scheme: Literal["http", "https"] = "http"
    authorized: Literal[True]
    authorization_note: str = Field(min_length=8, max_length=500)
    vm_id: str | None = None
    snapshot_id: str | None = None

    @field_validator("address")
    @classmethod
    def ip_literal(cls, value):
        return str(ipaddress.ip_address(value))

    @field_validator("ports")
    @classmethod
    def ports_valid(cls, values):
        if any(p < 1 or p > 65535 for p in values):
            raise ValueError("Ports must be in 1..65535")
        return sorted(set(values))

    @field_validator("vm_id", "snapshot_id")
    @classmethod
    def uuid_only(cls, value):
        if value is not None and not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value):
            raise ValueError("Use the VirtualBox UUID, not a name")
        return value.lower() if value else value


class JobInput(StrictModel):
    target_id: str
    objective: str = Field(min_length=8, max_length=2000)
    planner: Literal["ollama", "playbook"] = "ollama"
    allow_recovery_proposals: bool = False
    allowed_tools: list[str] | None = Field(default=None, max_length=12)

    @field_validator("allowed_tools")
    @classmethod
    def known_tools(cls, values):
        if values is not None and any(v not in {t.value for t in ToolName} for v in values):
            raise ValueError("Unknown tool name")
        return values


class ToolName(str, Enum):
    WEB = "web_assess"
    AUTHZ = "api_authz"
    SAMPLES = "review_samples"
    INFRA = "review_infrastructure"
    FUZZ = "fuzz_builtin_parser"
    NETWORK = "network_probe"
    INVENTORY = "host_inventory"
    EVENTS = "analyze_events"
    GRAPH = "attack_graph"
    HEAL = "propose_healing"
    FINISH = "finish"


class Decision(StrictModel):
    tool: ToolName
    reason: str = Field(min_length=1, max_length=500)


class EventInput(StrictModel):
    target_id: str
    source: Literal["operator", "collector", "lab_simulation"] = "operator"
    kind: Literal["process", "file", "network", "auth", "config"]
    process: str = Field(default="", max_length=200)
    path: str = Field(default="", max_length=500)
    destination: str = Field(default="", max_length=200)
    count: int = Field(default=1, ge=1, le=100000)
    failed: bool = False
    executable_write: bool = False
    persistence: bool = False
    encoded_command: bool = False


class FeedbackInput(StrictModel):
    malicious: bool
    reason: str = Field(min_length=12, max_length=500)
    validated: Literal[True]


class ApprovalInput(StrictModel):
    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=8, max_length=500)


class RecoveryInput(StrictModel):
    target_id: str
    action: Literal["lab_harden", "lab_restore", "vm_quarantine", "vm_reconnect", "vm_restore"]


class SampleInput(StrictModel):
    target_id: str
    name: str = Field(min_length=1, max_length=120)
    content_base64: str = Field(max_length=1400000)


class FuzzInput(StrictModel):
    seed: int = Field(default=42, ge=0, le=4294967295)
    iterations: int = Field(default=256, ge=1, le=1000)


class ManifestInput(StrictModel):
    target_id: str
    manifest: dict


def finite_features(features):
    return {k: min(1000.0, max(-1000.0, float(v))) for k, v in features.items() if math.isfinite(float(v))}
