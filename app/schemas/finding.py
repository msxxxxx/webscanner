from datetime import datetime
from pydantic import BaseModel


class FindingRead(BaseModel):
    id: int
    scan_id: int
    type: str
    severity: str | None
    title: str
    url: str | None
    evidence: dict

    model_config = {"from_attributes": True}