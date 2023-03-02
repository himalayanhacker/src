from fastapi import APIRouter
from views.user import router

api_router = APIRouter()


api_router.include_router(router, prefix="/user", tags=["user"])
