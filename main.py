tewimport os
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import OpenAI
from fastapi import Depends, HTTPException, Header
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from db import Base, engine, get_db
from auth import hash_password, verify_password, create_token, decode_token

from auth import pwd_context

from datetime import datetime, timedelta, date
from typing import List
from models import User, Event



app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://app.negynegyketto.eu",
        "http://app.negynegyketto.eu",
        "https://negynegyketto.eu",
        "http://negynegyketto.eu",
        "https://negynegyketto.eu",
        "http://negynegyketto.eu"

    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/debug/auth")
def debug_auth():
    return {"schemes": list(pwd_context.schemes())}

@app.on_event("startup")
def on_startup():
    try:
        Base.metadata.create_all(bind=engine)
        print("DB ready")
    except Exception as e:
        print("DB init failed:", repr(e))


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

import traceback
from fastapi import HTTPException

@app.post("/auth/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="E-Mail existiert bereits")

    # Mindestlänge
    pw = req.password.strip()
    
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Passwort zu kurz (min. 6)")

    if len(req.password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=400,
            detail="Passwort zu lang (max. 72 Zeichen)"
        )

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

class CalendarAIRequest(BaseModel):
    message: str

class RecurrenceRule(BaseModel):
    title: str = "Training"
    start_date: str           # "YYYY-MM-DD"
    end_date: str             # "YYYY-MM-DD"
    weekdays: List[str]       # ["MO","TU","WE","TH","FR","SA","SU"]
    time: str                 # "19:00"
    duration_minutes: int = 90
    type: str | None = "training"
    notes: str | None = None
    timezone: str | None = "Europe/Berlin"

class RecurrenceResponse(BaseModel):
    events: List[RecurrenceRule]

WEEKDAY_MAP = {
    "MO": 0, "TU": 1, "WE": 2, "TH": 3, "FR": 4, "SA": 5, "SU": 6
}

def expand_recurrence(rule: RecurrenceRule) -> List[tuple[datetime, datetime, str, str | None, str | None]]:
    # returns list of (start_dt, end_dt, title, type, notes)
    start_d = date.fromisoformat(rule.start_date)
    end_d = date.fromisoformat(rule.end_date)
    hh, mm = rule.time.split(":")
    hour = int(hh); minute = int(mm)

    wanted = set(WEEKDAY_MAP[d] for d in rule.weekdays if d in WEEKDAY_MAP)
    if not wanted:
        return []

    out = []
    cur = start_d
    while cur <= end_d:
        if cur.weekday() in wanted:
            start_dt = datetime(cur.year, cur.month, cur.day, hour, minute)
            end_dt = start_dt + timedelta(minutes=rule.duration_minutes)
            out.append((start_dt, end_dt, rule.title, rule.type, rule.notes))
        cur = cur + timedelta(days=1)
    return out

@app.post("/api/calendar/ai-plan")
def calendar_ai_plan(req: CalendarAIRequest, user: User = Depends(get_current_user)):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY fehlt")

    client = OpenAI(api_key=api_key)

    system = (
        "Du bist ein Assistent für Fußballtrainer und sollst aus dem Text Kalender-Regeln extrahieren.\n"
        "Gib NUR gültiges JSON zurück, ohne Markdown.\n"
        "Format:\n"
        "{ \"events\": [ {"
        "\"title\":\"Training\","
        "\"start_date\":\"YYYY-MM-DD\","
        "\"end_date\":\"YYYY-MM-DD\","
        "\"weekdays\":[\"MO\",\"TU\"...],"
        "\"time\":\"HH:MM\","
        "\"duration_minutes\":90,"
        "\"type\":\"training\","
        "\"notes\":\"...\","
        "\"timezone\":\"Europe/Berlin\""
        "} ] }\n"
        "Wenn ein Datum fehlt, nimm das heutige Jahr an und setze end_date = start_date + 90 Tage.\n"
        "Wenn Uhrzeit fehlt, nimm 19:00.\n"
        "Wenn Wochentage fehlen, nimm MO und DO.\n"
    )

    # responses API -> wir erwarten JSON im output_text
    resp = client.responses.create(
        model="gpt-4o-mini",
        input=f"{system}\nTEXT:\n{req.message}"
    )

    raw = resp.output_text.strip()

    try:
        data = __import__("json").loads(raw)
        parsed = RecurrenceResponse(**data)
        return parsed.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI JSON parse failed: {e}; raw={raw[:500]}")



class SaveRecurrenceRequest(BaseModel):
    rule: RecurrenceRule

@app.post("/api/calendar/save")
def calendar_save(req: SaveRecurrenceRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    items = expand_recurrence(req.rule)
    if not items:
        raise HTTPException(status_code=400, detail="Keine Termine aus Regel erzeugt")

    created = 0
    for start_dt, end_dt, title, typ, notes in items:
        ev = Event(
            user_id=user.id,
            title=title,
            start_at=start_dt,
            end_at=end_dt,
            type=typ,
            notes=notes
        )
        db.add(ev)
        created += 1

    db.commit()
    return {"ok": True, "created": created}

@app.get("/api/calendar/events")
def list_events(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    events = db.query(Event)\
        .filter(Event.user_id == user.id)\
        .order_by(Event.start_at)\
        .all()

    return [
        {
            "id": e.id,
            "title": e.title,
            "start": e.start_at.isoformat(),
            "end": e.end_at.isoformat(),
            "type": e.type,
            "notes": e.notes,
        }
        for e in events
    ]












