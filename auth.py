import os
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME")
JWT_ALG = "HS256"
JWT_EXPIRES_DAYS = 30

def hash_password(password: str) -> str:
    return pwd_context.hash(password)
    print("PW_LEN_BYTES:", len(req.password.encode("utf-8")))


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)

def create_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRES_DAYS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> int:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    return int(payload["sub"])
