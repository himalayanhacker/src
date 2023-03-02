from schemas import auth
from sqlalchemy.orm import Session
from models.auth import User, OTP
from utils.authentication import Authenticate, JWTBearer
from fastapi import Depends, HTTPException, status, Request
from config import setting
from jose import JWTError, jwt
from app_db import get_db


auth_service = Authenticate()


async def create_user(new_user: auth.UserCreate, db: Session):
    user = User(
        email=new_user.email,
        first_name=new_user.first_name,
        last_name=new_user.last_name,
        phone=new_user.phone,
        password=auth_service.hash_password(password=new_user.password),
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


async def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()


async def get_all_user(db: Session):
    return db.query(User).filter().all()


async def get_user_by_email(db: Session, email: str):
    found_user = db.query(User).filter(User.email == email).first()
    return auth.UserInDb.from_orm(found_user)


async def existing_email(db: Session, email: str):
    user_obj = db.query(User).filter(User.email == email).first()
    if user_obj:
        return user_obj


async def get_current_user(
        token: str = Depends(JWTBearer()), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(
            token, setting.SECRET_KEY, algorithms=[setting.JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Email Not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token_data = auth.TokenData(email=email)
    except JWTError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{err}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err
    try:
        user = db.query(User).filter(User.email == token_data.email).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User Not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{e}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


async def get_current_active_user(
        current_user: User = Depends(get_current_user)):
    return current_user


async def verify_token(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(
            token, setting.SECRET_KEY, algorithms=[setting.JWT_ALGORITHM])
        user = db.query(User).filter(
                User.email == payload.get('sub')).first()
    except JWTError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err

    return user


async def create_otp_token(
        otp_user: auth.OTPBase, user: Request, otp: int,
        db: Session = Depends(get_db)):
    otp_user = OTP(
        email=otp_user.email,
        code=otp,
        created_at=otp_user.created_at,
        user_id=otp_user.id
    )
    db.add(otp_user)
    db.commit()
    db.refresh(otp_user)
    return otp_user


async def get_otp(otp: int, db: Session = Depends(get_db)):
    return db.query(OTP).filter(OTP.code == otp).first()


async def update_user(user_id: int, user: auth.UserBase, db: Session):
    exist_user = db.query(User).filter(User.id == user_id).first()
    exist_user.first_name = user.first_name
    exist_user.last_name = user.last_name
    exist_user.phone = user.phone
    exist_user.updated_at = user.updated_at
    db.commit()
    db.refresh(exist_user)
    return exist_user


async def delete_user(user_id: int, db: Session):
    user = db.query(User).filter(User.id == user_id).first()
    db.delete(user)
    db.commit()
    return True
