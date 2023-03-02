from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from schemas.auth import UserInDb, JWTMeta, JWTCreds, JWTPayload
from config import setting
from datetime import datetime, timedelta
from jose import jwt


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Authenticate:
    @staticmethod
    def verify_password(plain_password, hashed_password):
        """Verify Password
        Args:
            plain_password (str): password
            hashed_password (str): hash_password

        Returns:
            bool: True/False
        """
        verify = pwd_context.verify(plain_password, hashed_password)
        return verify

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash Password

        Args:
            password (str): password

        Returns:
            str: password
        """
        return pwd_context.hash(password)

    @staticmethod
    def create_access_token_for_user(
            user: UserInDb, secret_key: str = str(setting.SECRET_KEY),
            expires_in: int = setting.ACCESS_TOKEN_EXPIRE_MINUTES
            ):
        """Create access Token

        Args:
            user (UserInDb): user
            secret_key (str, optional): secret_key
            expires_in (int, optional): ACCESS_TOKEN_EXPIRE_MINUTES.

        Returns:
            str: access token
        """
        if not user and not isinstance(user, UserInDb):
            return None
        jwt_meta = JWTMeta(
            iat=datetime.timestamp(datetime.now()),
            exp=datetime.timestamp(
                datetime.now() + timedelta(minutes=expires_in)),
        )
        jwt_creds = JWTCreds(sub=user.email)

        token_payload = JWTPayload(
            **jwt_meta.dict(),
            **jwt_creds.dict()
        )

        return jwt.encode(
            token_payload.dict(), secret_key, algorithm=setting.JWT_ALGORITHM)

    def create_refresh_token(
            self, user: UserInDb,
            refresh_secret_key: str = str(setting.JWT_REFRESH_SECRET_KEY),
            expires_in: int = setting.REFRESH_TOKEN_EXPIRE_MINUTES):
        """Create Refresh Token

        Args:
            user (UserInDb): user
            secret_key (str, optional): JWT_REFRESH_SECRET_KEY
            expires_in (int, optional): REFRESH_TOKEN_EXPIRE_MINUTES.

        Returns:
            str: Refresh token
        """
        if not user and not isinstance(user, UserInDb):
            return None
        jwt_meta = JWTMeta(
            iat=datetime.timestamp(datetime.now()),
            exp=datetime.timestamp(
                datetime.now() + timedelta(minutes=expires_in)),
        )
        jwt_creds = JWTCreds(sub=user.email)

        token_payload = JWTPayload(
            **jwt_meta.dict(),
            **jwt_creds.dict()
        )

        return jwt.encode(
            token_payload.dict(), refresh_secret_key,
            algorithm=setting.JWT_ALGORITHM)


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(
            JWTBearer, self).__call__(request)
        if not credentials:
            raise HTTPException(
                status_code=403, detail="Invalid authorization code.")
        if not credentials.scheme == "Bearer":
            raise HTTPException(
                status_code=403, detail="Invalid authentication scheme.")
        return credentials.credentials
