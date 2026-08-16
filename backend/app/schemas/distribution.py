"""Ephemeral Distribution Pydantic schemas."""

from pydantic import BaseModel


class StreamPurgeResponse(BaseModel):
    exam_id: str
    purged: bool
    status: str
    message: str
