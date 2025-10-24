from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from fastapi import APIRouter
from .models import create_session, Admin, get_db_engine
from passlib.context import CryptContext
import os

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
router = APIRouter()

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_admin_by_username(db: Session, username: str):
    return db.query(Admin).filter(Admin.username == username).first()


@router.post("/admin/login")
def admin_login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Minimal admin login endpoint. Use form fields: username, password"""
    engine = get_db_engine()
    SessionLocal = create_session(engine)
    db = SessionLocal()
    try:
        admin = get_admin_by_username(db, form_data.username)
        if not admin or not verify_password(form_data.password, admin.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
        token = create_access_token({"sub": admin.username})
        return {"access_token": token, "token_type": "bearer"}
    finally:
        db.close()
