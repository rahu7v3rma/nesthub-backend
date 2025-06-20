import re
from typing import Literal

from pydantic import BaseModel, EmailStr, field_validator


class SignupRequest(BaseModel):
    name: str
    company: str
    license_id: str
    phone: str
    email: EmailStr
    user_type: Literal['user', 'realtor']
    password: str

    @field_validator('password')
    @classmethod
    def validate_password(cls, password: str) -> str:
        if not re.match(
            r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^A-Za-z0-9]).{8,}$', password
        ):
            raise ValueError(
                (
                    'Password must contain at least 8 characters and contain '
                    '(Uppercase, Lowercase, special character and number)'
                )
            )
        return password
