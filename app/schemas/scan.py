from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field


ScanType = Literal["tcp", "ssl", "headers", "cert", "dirsearch", "nuclei"]


class ScanCreate(BaseModel):
    host: str = Field(..., min_length=1, max_length=255)
    scan_types: list[ScanType] = Field(default_factory=lambda: ["tcp"])
    web_ports: list[int] | None = Field(
        default=None,
        description="Порты для dirsearch/nuclei. None/пусто = все найденные web-порты.",
    )
    tcp_ports: list[int] | None = Field(
        default=None,
        description="Порты для nmap. None = top-1000. Пустой список = все (-p-).",
    )


class ScanRead(BaseModel):
    id: int
    target_id: int
    status: str
    scan_types: list[str]
    web_ports: list[int] | None = None
    tcp_ports: list[int] | None = None
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanStatus(BaseModel):
    id: int
    status: str
    error: str | None
    findings_count: int
    urls_count: int

    model_config = {"from_attributes": True}


class ScanListItem(BaseModel):
    id: int
    status: str
    scan_types: list[str]
    created_at: datetime
    finished_at: datetime | None
    target_id: int
    target_host: str
    findings_count: int = 0
    urls_count: int = 0