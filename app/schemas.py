"""Shared validation models for IOC evidence records."""
from datetime import datetime

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    ioc: str = Field(strict=True)
    ioc_type: str
    source: str
    finding: str
    verdict: str
    confidence: str
    timestamp: datetime
    reference: str
