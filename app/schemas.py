"""Pydantic request/response models for Ziva."""

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL to analyze (never fetched)")


class FindingSchema(BaseModel):
    rule_id: str
    title: str
    severity: Literal["low", "medium", "high"]
    explanation: str


class ParsedURLSchema(BaseModel):
    scheme: str
    hostname: str
    registered_domain: str
    subdomains: List[str]
    path: str
    port: Optional[int] = None


class AnalyzeResponse(BaseModel):
    url: str
    normalized_url: str
    defanged_url: str
    score: int = Field(..., ge=0, le=100)
    verdict: Literal["Safe", "Suspicious", "High Risk"]
    findings: List[FindingSchema]
    parsed: ParsedURLSchema


class HealthResponse(BaseModel):
    status: str
    app: str
    tagline: str
    version: str
