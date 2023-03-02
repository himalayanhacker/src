from sqlalchemy import (
    Column,
    String,
    Unicode,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    BigInteger,
    Enum
)
from app_db import Base
import enum
import datetime


class OTPTypeEnum(enum.Enum):
    forgotpassword = 'forgotpassword'
    resetpassword = 'resetpassword'


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    phone = Column(BigInteger, nullable=True)
    password = Column(Unicode)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, nullable=True, default=datetime.datetime.now)
    updated_at = Column(DateTime, nullable=True)


class OTP(Base):
    __tablename__ = 'otps'
    id = Column(Integer, primary_key=True, index=True)
    type = Column(
        Enum(OTPTypeEnum),
        default=OTPTypeEnum.forgotpassword, nullable=False)
    email = Column(String)
    code = Column(Integer)
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, nullable=True, default=datetime.datetime.now)
    updated_at = Column(DateTime, nullable=True)
