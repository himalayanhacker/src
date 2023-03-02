from pydantic import BaseSettings, validator
from typing import Optional, Dict, Any
from pydantic import EmailStr


class Settings(BaseSettings):
    database_user: str
    database_password: str
    database_host: str
    database_port: int
    database_name: str

    JWT_SETTINGS: Optional[Dict[str, Any]] = None
    SECRET_KEY: str
    JWT_ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    JWT_TOKEN_PREFIX: str
    REFRESH_TOKEN_EXPIRE_MINUTES: int
    JWT_REFRESH_SECRET_KEY: str

    EMAIl_FROM: EmailStr
    EMAIL_PASSWORD: str
    EMAIL_PORT: str
    EMAIL_HOST: str

    @validator("JWT_SETTINGS", pre=True)
    def assemble_jwt_settings(
            cls, v: Optional[str], values: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(v, cls):
            return v
        return {
            "SECRET_KEY": values.get("SECRET_KEY"),
            "JWT_ALGORITHM": values.get('JWT_ALGORITHM'),
            "ACCESS_TOKEN_EXPIRE_MINUTES": values.get(
                "ACCESS_TOKEN_EXPIRE_MINUTES"),
            "JWT_TOKEN_PREFIX": values.get("JWT_TOKEN_PREFIX"),
            "JWT_REFRESH_SECRET_KEY": values.get("JWT_REFRESH_SECRET_KEY"),
            "REFRESH_TOKEN_EXPIRE_MINUTES": values.get(
                                    "REFRESH_TOKEN_EXPIRE_MINUTES"),
        }

    class Config:
        env_file = ".env"


setting = Settings()
