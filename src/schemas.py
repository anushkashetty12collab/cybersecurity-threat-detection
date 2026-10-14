"""Task 4: input validation (pydantic v2) for JSON bodies and uploaded files."""
import ipaddress
from datetime import datetime
from typing import Literal, Optional

import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

REQUIRED_COLUMNS = ["timestamp", "source_ip", "dest_ip", "asset", "user",
                    "event_type", "status", "port", "bytes_out"]
MAX_EVENTS = 50_000


class LogEvent(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)
    timestamp: datetime
    source_ip: str
    dest_ip: str
    asset: str = Field(min_length=1, max_length=64)
    user: str = Field(min_length=1, max_length=64)
    event_type: Literal["login", "file_access", "network_conn", "admin_action"]
    status: Literal["success", "failure"]
    port: int = Field(ge=0, le=65535)
    bytes_out: float = Field(ge=0, le=1e12)
    event_id: Optional[int] = None

    @field_validator("source_ip", "dest_ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")
        return v


class AnalyzeRequest(BaseModel):
    logs: list[LogEvent] = Field(min_length=1, max_length=MAX_EVENTS)
    enrich: bool = True


def events_to_dataframe(events: list[LogEvent]) -> pd.DataFrame:
    return _normalise(pd.DataFrame([e.model_dump() for e in events]))


def validate_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Validate an uploaded table row by row. Raises ValueError with a readable message."""
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required column(s): {', '.join(missing)}")
    if df.empty:
        raise ValueError("The file contains no rows")
    if len(df) > MAX_EVENTS:
        raise ValueError(f"Too many rows ({len(df)}); maximum is {MAX_EVENTS}")
    errors = []
    for i, rec in enumerate(df[REQUIRED_COLUMNS].to_dict("records")):
        try:
            LogEvent(**rec)
        except ValidationError as e:
            err = e.errors()[0]
            errors.append(f"row {i + 1}, field '{err['loc'][0]}': {err['msg']}")
            if len(errors) >= 5:
                break
    if errors:
        raise ValueError("Invalid data: " + "; ".join(errors))
    return _normalise(df)


def _normalise(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True).dt.tz_localize(None)
    return df
