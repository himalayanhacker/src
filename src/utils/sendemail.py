from typing import List
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import EmailStr, BaseModel
from config import setting
from utils.authentication import Authenticate


auth_service = Authenticate()


conf = ConnectionConfig(
        MAIL_FROM=setting.EMAIl_FROM,
        MAIL_USERNAME=setting.EMAIl_FROM,
        MAIL_PASSWORD=setting.EMAIL_PASSWORD,
        MAIL_PORT=setting.EMAIL_PORT,
        MAIL_SERVER=setting.EMAIL_HOST,
        MAIL_STARTTLS=True,
        MAIL_SSL_TLS=False,
        USE_CREDENTIALS=True,
        VALIDATE_CERTS=True
    )


class EmailSchema(BaseModel):
    email: List[EmailStr]


async def send_email(email: list):
    token = auth_service.create_access_token_for_user(user=email)
    email_list = [email.email]
    template = f"""
        <!DOCTYPE html>
        <html>
        <head>
        </head>
        <body>
            <div style=" display: flex; align-items: center; justify-content: center; flex-direction: column;">
                <h3> Account Verification </h3>
                <br>
                <p>Please, Click on the link below to verify your account</p>
                <a style="margin-top:1rem; padding: 1rem; border-radius: 0.5rem; font-size: 1rem; text-decoration: none; background: #0275d8; color: white;"
                 href="http://127.0.0.1:8000/api/v1/user/verification/?token={token}">
                    Verify your email
                </a>
                <p style="margin-top:1rem;">If you did not register,
                Please kindly ignore this email and nothing will happen.Thanks<p>
            </div>
        </body>
        </html>
    """

    message = MessageSchema(
        subject="Account Verification Mail",
        recipients=email_list,
        body=template,
        subtype="html"
        )

    fm = FastMail(conf)
    await fm.send_message(message)


async def send_otp(email: list, otp: int):
    otp = otp
    email_list = [email.email]
    template = f"""
        <!DOCTYPE html>
        <html>
        <head>
        </head>
        <body>
            <div style=" display: flex; align-items: center; justify-content: center; flex-direction: column;">
                <h3>OTP Verification</h3>
                <br>
                <p>Copy the Code</p>
                <div style="margin-top:1rem; padding: 1rem; border-radius: 0.5rem; font-size: 1rem; text-decoration: none; background: black; color: white;">
                    {otp}
                </div>
            </div>
        </body>
        </html>
    """

    message = MessageSchema(
        subject="OTP link",
        recipients=email_list,
        body=template,
        subtype="html"
        )

    fm = FastMail(conf)
    await fm.send_message(message)
