import os
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import OpenAI
from fastapi import Depends, HTTPException, Header
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from db import Base, engine, get_db
from models import User
from auth import hash_password, verify_password, create_token, decode_token


app = FastAPI()

# 2) CORS EINMAL
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://app.negynegyketto.eu",
        "http://app.negynegyketto.eu",
        "https://negynegyketto.eu",
        "http://negynegyketto.eu",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    club_name: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization.split(" ", 1)[1]
    user_id = decode_token(token)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user
    
@app.post("/auth/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email.lower().strip()).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Login fehlgeschlagen")

    token = create_token(user.id)
    return {"token": token}

@app.post("/auth/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="E-Mail existiert bereits")

    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Passwort zu kurz (min. 6)")

    user = User(
        email=req.email.lower().strip(),
        password_hash=hash_password(req.password),
        club_name=req.club_name.strip(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"ok": True}


@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"email": user.email, "club_name": user.club_name}

class CoachRequest(BaseModel):
    message: str
    team: Optional[str] = None
    age_group: Optional[str] = None

@app.get("/health")
def health():
    return {"ok": True}

from fastapi import HTTPException
import traceback

@app.post("/api/coach")
def coach(req: CoachRequest):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return {"reply": "OPENAI_API_KEY fehlt. Setze die Umgebungsvariable und starte neu."}

    try:
        client = OpenAI(api_key=api_key)

        system = (
            "Du bist ein Fußball-Assistenztrainer. Antworte kurz und praktisch in Stichpunkten. "
            "Gib konkrete Trainingsvorschläge (Dauer, Inhalte, Spielformen)."
        )

        # WICHTIG: nimm erstmal ein sehr gängiges Modell
        resp = client.responses.create(
            model="gpt-4o-mini",
            input=f"{system}\nTrainer-Frage: {req.message}",
        )

        return {"reply": resp.output_text}

    except Exception as e:
        # Gibt dir die echte Fehlermeldung zurück (nur lokal! später wieder entfernen)
        details = f"{type(e).__name__}: {e}\n\n{traceback.format_exc()}"
        raise HTTPException(status_code=500, detail=details)






