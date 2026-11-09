from datetime import datetime
from pydantic import BaseModel, Field


class TargetCreate(BaseModel):
    host: str = Field(..., min_length=1, max_length=255, examples=["example.com"])


class TargetRead(BaseModel):
    id: int
    host: str
    ip: str | None
    created_at: datetime

    model_config = {"from_attributes": True}