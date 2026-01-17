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

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://app.negynegyketto.eu",
        "http://app.negynegyketto.eu",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

