from pydantic import BaseModel, EmailStr, constr, validator
from typing import Optional, Union
from datetime import datetime, timedelta
from config import setting


class CoreModel(BaseModel):
    pass


class DateTimeModel(BaseModel):
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    @validator("created_at", "updated_at", pre=True, always=True)
    def default_datetime(cls, value: datetime) -> datetime:
        return value or datetime.now()


class PhoneBase(BaseModel):
    phone: Optional[constr(
        strip_whitespace=True,
        regex=r"^(\+)[1-9](?P<separator>[\-\(\)\.]?)(?P<digits>[0-9]{3}(?P=separator)?[0-9]{3}(?P=separator)?[0-9]{4})$"
    )]


class UserBase(CoreModel, DateTimeModel, PhoneBase):
    email: Optional[EmailStr] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[int] = None
    is_active: bool = False


class UserCreate(CoreModel, PhoneBase):
    email: EmailStr
    first_name: Optional[str]
    last_name: Optional[str]
    password: constr(min_length=7, max_length=100)


class UserInDb(UserBase):
    password: constr(min_length=7, max_length=100)

    class Config:
        orm_mode = True


class User(UserBase, BaseModel):
    id: int
    is_active: bool

    class Config:
        orm_mode = True


# Add JWT Schemas

class JWTMeta(CoreModel):
    iat: float = datetime.timestamp(datetime.now())
    exp: float = datetime.timestamp(
        datetime.now() + timedelta(
            minutes=setting.ACCESS_TOKEN_EXPIRE_MINUTES))


class JWTCreds(CoreModel):
    sub: EmailStr


class JWTPayload(JWTMeta, JWTCreds):
    pass


class AccessToken(CoreModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserPubllic(UserBase):
    access_token: Optional[AccessToken]

    class Config:
        orm_mode = True


# class UserLogin(CoreModel):
#     email: EmailStr
#     password: constr(min_length=7, max_length=100)


class TokenData(CoreModel):
    email: Union[EmailStr, None] = None


class OTPBase(CoreModel, DateTimeModel):
    email: EmailStr


class UserPasswordUpdate(DateTimeModel):
    otp: int
    new_password: constr(min_length=7, max_length=100)
    confirm_password: constr(min_length=7, max_length=100)


class ResetPassword(UserBase):
    old_password: constr(min_length=7, max_length=100)
    new_password: constr(min_length=7, max_length=100)
