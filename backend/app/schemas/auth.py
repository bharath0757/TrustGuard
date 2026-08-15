"""Auth request and response Pydantic schemas."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)
    role: str = Field(..., pattern="^(ADMIN|EXAM_SETTER|KEY_GUARDIAN|EXAM_CENTER|AUDITOR)$")


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user_id: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
