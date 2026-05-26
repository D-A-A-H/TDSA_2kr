from pydantic import BaseModel, EmailStr, Field
from typing import Optional


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    age: Optional[int] = Field(None, ge=1, description="Age must be positive integer")
    is_subscribed: Optional[bool] = False


class LoginRequest(BaseModel):
    username: str
    password: str


class ProfileResponse(BaseModel):
    user_id: str
    username: str
    message: str