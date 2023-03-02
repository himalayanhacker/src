from fastapi import (
    APIRouter,
    Depends,
    Response,
    Request,
    HTTPException,
    status,
    Form
)
from schemas.auth import (
    User,
    UserCreate,
    UserBase,
    # UserLogin,
    AccessToken,
    OTPBase,
    UserPasswordUpdate,
    ResetPassword,
)
from sqlalchemy.orm import Session
from app_db import get_db
from db.auth import (
    create_user,
    get_all_user,
    get_user_by_id,
    get_user_by_email,
    existing_email,
    get_current_active_user,
    create_otp_token,
    get_otp,
    update_user,
    delete_user,
)
from utils.authentication import Authenticate, JWTBearer
from utils.response import response as custom_response
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from db.auth import verify_token
from utils.sendemail import send_email, send_otp
import random
from models.auth import User as ModelUser


auth_service = Authenticate()


router = APIRouter()


@router.post("/create/")
async def create_new_user(
        new_user: UserCreate, response: Response,
        db: Session = Depends(get_db)):
    status_code = 200
    status = True
    message = "Success"
    return_data = {}
    try:
        user_obj = await existing_email(email=new_user.email, db=db)
        if user_obj:
            status_code = 403
            status = False
            message = "Already Exist"
            response.status_code = 403
        else:
            new_user_create = await create_user(new_user=new_user, db=db)
            await send_email(email=new_user_create)
            status_code = 201
            status = True
            message = "User Created, please Check MAil"
            response.status_code = 201
            return_data = new_user_create
    except Exception as e:
        status_code = 400
        status = False
        message = f"{e}"
        response.status_code = 400
    return custom_response(
            data=return_data, status=status, code=status_code,
            message=message
        )


@router.get("/users/", dependencies=[Depends(JWTBearer())])
async def get_users(response: Response, db: Session = Depends(get_db)):
    status_code = 200
    status = True
    message = "Success"
    return_data = {}
    try:
        users = await get_all_user(db=db)
        message = "All Users"
        return_data = users
        if not return_data:
            status_code = 404
            status = False
            message = "not found"
            response.status_code = 404
    except Exception as e:
        status_code = 400
        status = False
        message = f"{e}"
    return custom_response(
            data=return_data, status=status, code=status_code,
            message=message
        )


@router.get("/user/{user_id}", dependencies=[Depends(JWTBearer())])
async def get_user_id(
        user_id: int, response: Response, db: Session = Depends(get_db)):
    status_code = 200
    status = True
    message = "Success"
    return_data = {}
    try:
        user = await get_user_by_id(user_id=user_id, db=db)
        message = "User Found"
        return_data = user
        if not return_data:
            status_code = 404
            status = False
            message = "not found"
            response.status_code = 404
            return_data = {}
    except Exception as e:
        status_code = 400
        status = False
        message = f"{e}"
        response.status_code = 400
    return custom_response(
        data=return_data, status=status, code=status_code,
        message=message
    )


@router.patch("/updateuser/{user_id}", dependencies=[Depends(JWTBearer())])
async def update_exist_user(
        user_id: int, userbase: UserBase, response: Response,
        db: Session = Depends(get_db)):
    status_code = 200
    status = True
    message = "Success"
    return_data = {}
    try:
        user = await get_user_by_id(user_id=user_id, db=db)
        if not user:
            status_code = 404
            status = False
            message = "user not found"
            response.status_code = 404
        else:
            user_updated = await update_user(
                user_id=user.id, user=userbase, db=db)
            message = "User Updated Successfully"
            return_data = user_updated
    except Exception as err:
        status_code = 400
        status = False
        message = f"{err}"
        response.status_code = 400
    return custom_response(
        data=return_data, status=status, code=status_code,
        message=message)


@router.delete("/deleteuser/{user_id}")
async def delete_exist_user(
        user_id: int, response: Response, db: Session = Depends(get_db)):
    status_code = 200
    status = True
    message = "Success"
    return_data = {}
    try:
        user = await get_user_by_id(user_id=user_id, db=db)
        if not user:
            status_code = 404
            status = False
            message = "user not found"
            response.status_code = 404
        else:
            await delete_user(
                user_id=user.id, db=db)
            message = "User Deleted Successfully"
            status_code = 200
            response.status_code = 200
            return_data = {}
    except Exception as err:
        status_code = 400
        status = False
        message = f"{err}"
        response.status_code = 400
    return custom_response(

        data=return_data, status=status, code=status_code,
        message=message)


@router.post(
    "/login", description="Log In the User",
    )
# async def user_login(
#         user: UserLogin, response: Response, db: Session = Depends(get_db)):
async def user_login(
        response: Response, email: str = Form(...), password: str = Form(...),
        db: Session = Depends(get_db)
):
    status_code = 200
    status = True
    message = "Success"
    return_data = {}
    try:
        # found_user = await get_user_by_email(email=user.email, db=db)
        found_user = await get_user_by_email(email=email, db=db)
        if not found_user:
            status_code = 404
            status = False
            message = "not found"
            response.status_code = 404
            return_data = {}
        # elif not auth_service.verify_password(
        #             plain_password=user.password,
        #             hashed_password=found_user.password
        #         ):
        elif not auth_service.verify_password(
                    plain_password=password,
                    hashed_password=found_user.password
                ):
            status_code = 401
            status = False
            message = "Password is not verified"
            response.status_code = 401
            return_data = {}
        elif found_user.is_active is False:
            status_code = 401
            status = False
            message = "User is not active"
            response.status_code = 401
            return_data = {}
        else:
            token = auth_service.create_access_token_for_user(user=found_user)
            refresh_token = auth_service.create_refresh_token(user=found_user)
            token = AccessToken(
                access_token=token, refresh_token=refresh_token,
                token_type="bearer")
            status_code = 200
            status = True
            response.status_code = 200
            message = "Login Successfully"
            return_data = token
    except Exception as e:
        status_code = 400
        status = False
        message = f"{e}"
        response.status_code = 400
    return custom_response(
            data=return_data, status=status, code=status_code,
            message=message
        )


@router.get("/me/", dependencies=[Depends(JWTBearer())])
async def read_users_me(
        response: Response,
        current_user: User = Depends(get_current_active_user)):
    status_code = 200
    status = True
    message = "Success"
    return_data = {}
    try:
        return_data = current_user
    except Exception as e:
        status_code = 400
        status = False
        message = f"{e}"
        response.status_code = 400
    return custom_response(
            data=return_data, status=status, code=status_code,
            message=message
        )


templates = Jinja2Templates(directory="templates")


@router.get('/verification',  response_class=HTMLResponse)
async def email_verification(
        request: Request, token: str, db: Session = Depends(get_db)):
    user = await verify_token(token, db)
    if user and not user.is_active:
        user.is_active = True
        db.add(user)
        db.commit()
        db.refresh(user)
        return templates.TemplateResponse(
            "verification.html",
            {"request": request, "email": user.email}
        )
    else:
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )


@router.post("/forgotpassword")
async def forgot_password(
        request: OTPBase, user: Request, response: Response,
        db: Session = Depends(get_db)):
    status_code = 200
    status = True
    message = "Success"
    return_data = {}
    try:
        found_user = await existing_email(email=request.email, db=db)
        if not found_user:
            status_code = 404
            status = False
            message = "Email not found"
            return_data = {}
        else:
            otp = str(random.randint(100000, 999999))
            otp_user = await create_otp_token(
                otp_user=found_user, otp=otp, user=user, db=db)
            print(otp)
            await send_otp(email=otp_user, otp=otp)
            status_code = 200
            status = True
            message = "OTP Generated, Please Check mail"
    except Exception as e:
        status_code = 400
        status = False
        message = f"{e}"
        response.status_code = 400
    return custom_response(
            data=return_data, status=status, code=status_code,
            message=message
        )


@router.put("/savepassword")
async def save_password(
        update_pass_user: UserPasswordUpdate, response: Response,
        db: Session = Depends(get_db)):
    status_code = 200
    status = True
    message = "Success"
    return_data = {}
    try:
        user_otp = await get_otp(otp=update_pass_user.otp, db=db)
        if not user_otp:
            status_code = 404
            status = False
            message = "otp not found"
            return_data = {}
        elif (
            update_pass_user.new_password !=
                update_pass_user.confirm_password):
            status_code = 401
            status = False
            response.status_code = 401
            message = "Both password are not match"
            return_data = {}
        else:
            user_email = db.query(ModelUser).filter(
                ModelUser.email == user_otp.email).first()
            user_email.password = auth_service.hash_password(
                password=update_pass_user.new_password)
            user_email.updated_at = update_pass_user.updated_at
            db.delete(user_otp)
            db.commit()
            db.refresh(user_email)
            message = "Password Updated Successfully"
            response.status_code = 200
            return_data = user_email
    except Exception as e:
        status_code = 400
        status = False
        message = f"{e}"
        response.status_code = 400
    return custom_response(
            data=return_data, status=status, code=status_code,
            message=message
        )


@router.post("/resetpassword", dependencies=[Depends(JWTBearer())])
async def reset_password(
        user: ResetPassword,
        response: Response,
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db)):
    status_code = 200
    status = True
    message = "Success"
    return_data = {}
    try:
        oldpassword = auth_service.verify_password(
                plain_password=user.old_password,
                hashed_password=current_user.password)
        if not oldpassword:
            status_code = 401
            status = False
            message = "Old Password is not verified"
            response.status_code = 401
            return_data = {}
        else:
            user_obj = db.query(ModelUser).filter(
                ModelUser.email == current_user.email).first()
            user_obj.password = auth_service.hash_password(
                password=user.new_password)
            user_obj.updated_at = user.updated_at
            db.commit()
            db.refresh(user_obj)
            message = "Reset Password Successfully"
            response.status_code = 200
            return_data = user_obj
    except Exception as e:
        status_code = 400
        status = False
        message = f"{e}"
        response.status_code = 400
    return custom_response(
            data=return_data, status=status, code=status_code,
            message=message
        )
