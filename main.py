import os
import json
import traceback
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, ConfigDict
from sqlalchemy.orm import Session
from openai import OpenAI
from sqlalchemy import and_


from datetime import datetime, timedelta, date, time

from db import engine, get_db
from models import User, Event
from auth import hash_password, verify_password, create_token, decode_token
from auth import pwd_context


app = FastAPI()

# ---------- CORS ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://app.aicotrainer.eu",
        "http://app.aicotrainer.eu",
        "https://aicotrainer.eu",
        "http://aicotrainer.eu",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Startup ----------
@app.on_event("startup")
def on_startup():
    try:
        Base.metadata.create_all(bind=engine)
        print("DB ready")
        print("AUTH_SCHEME:", pwd_context.schemes())
    except Exception as e:
        print("DB init failed:", repr(e))


@app.get("/debug/auth")
def debug_auth():
    return {"schemes": list(pwd_context.schemes())}


# ---------- Auth Models ----------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    club_name: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# ---------- Token Helper ----------

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


# ---------- Register/Login ----------
@app.post("/auth/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == req.email.lower().strip()).first()
    if existing:
        raise HTTPException(status_code=400, detail="E-Mail existiert bereits")

    pw = req.password.strip()

    if len(pw) < 6:
        raise HTTPException(status_code=400, detail="Passwort zu kurz (min. 6)")

    if len(pw.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Passwort zu lang (max. 72 Zeichen)")

    user = User(
        email=req.email.lower().strip(),
        password_hash=hash_password(pw),
        club_name=req.club_name.strip(),
        # optional fields (wenn in models.py vorhanden)
        first_name=None,
        last_name=None,
        language="de",
        timezone="Europe/Berlin",
        date_format="dd.MM.yyyy",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"ok": True}


@app.post("/auth/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email.lower().strip()).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Login fehlgeschlagen")

    token = create_token(user.id)
    return {"token": token}


# ---------- ME (GET + PUT) ----------
@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {
        "email": user.email,
        "club_name": user.club_name,
        "first_name": getattr(user, "first_name", None),
        "last_name": getattr(user, "last_name", None),
        "language": getattr(user, "language", "de") or "de",
        "timezone": getattr(user, "timezone", "Europe/Berlin") or "Europe/Berlin",
        "date_format": getattr(user, "date_format", "dd.MM.yyyy") or "dd.MM.yyyy",
    }


class UpdateMeRequest(BaseModel):
    club_name: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    language: str | None = None
    timezone: str | None = None
    date_format: str | None = None
    password: str | None = None





@app.put("/me")
def update_me(
    req: UpdateMeRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if req.club_name is not None:
        user.club_name = req.club_name.strip() or user.club_name

    if req.first_name is not None:
        user.first_name = req.first_name.strip() or None

    if req.last_name is not None:
        user.last_name = req.last_name.strip() or None

    if req.language is not None:
        user.language = req.language.strip() or "de"

    if req.timezone is not None:
        user.timezone = req.timezone.strip() or "Europe/Berlin"

    if req.date_format is not None:
        user.date_format = req.date_format.strip() or "dd.MM.yyyy"

    if req.password:
        pw = req.password.strip()
        if len(pw) < 6:
            raise HTTPException(status_code=400, detail="Passwort zu kurz (min. 6)")
        if len(pw.encode("utf-8")) > 72:
            raise HTTPException(status_code=400, detail="Passwort zu lang (max. 72 Zeichen)")
        user.password_hash = hash_password(pw)

    db.add(user)
    db.commit()
    db.refresh(user)

    return {"ok": True}


# ---------- Health ----------
@app.get("/health")
def health():
    return {"ok": True}


# ---------- Coach ----------
class CoachRequest(BaseModel):
    message: str
    team: Optional[str] = None
    age_group: Optional[str] = None


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

        resp = client.responses.create(
            model="gpt-4o-mini",
            input=f"{system}\nTrainer-Frage: {req.message}",
        )

        return {"reply": resp.output_text}

    except Exception as e:
        details = f"{type(e).__name__}: {e}\n\n{traceback.format_exc()}"
        raise HTTPException(status_code=500, detail=details)


# ---------- Calendar AI ----------
class CalendarAIRequest(BaseModel):
    message: str

class RecurrenceRule(BaseModel):
    title: str = "Training"
    start_date: str          # "YYYY-MM-DD"
    end_date: str            # "YYYY-MM-DD"
    weekdays: List[str]      # ["MO","TU","WE","TH","FR","SA","SU"]
    time: str                # "19:00"
    duration_minutes: int = 90
    type: str | None = "training"
    notes: str | None = None
    timezone: str | None = "Europe/Berlin"

class RecurrenceResponse(BaseModel):
    events: List[RecurrenceRule]


WEEKDAY_MAP = {"MO": 0, "TU": 1, "WE": 2, "TH": 3, "FR": 4, "SA": 5, "SU": 6}

def expand_recurrence(rule: RecurrenceRule):
    start_d = date.fromisoformat(rule.start_date)
    end_d = date.fromisoformat(rule.end_date)
    hh, mm = rule.time.split(":")
    hour = int(hh)
    minute = int(mm)

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
        cur += timedelta(days=1)
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

    resp = client.responses.create(
        model="gpt-4o-mini",
        input=f"{system}\nTEXT:\n{req.message}"
    )

    raw = (resp.output_text or "").strip()

    try:
        data = json.loads(raw)
        parsed = RecurrenceResponse(**data)
        return parsed.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI JSON parse failed: {e}; raw={raw[:500]}")


class SaveRecurrenceRequest(BaseModel):
    rule: RecurrenceRule


from sqlalchemy.exc import IntegrityError

@app.post("/api/calendar/save")
def calendar_save(
    req: SaveRecurrenceRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    items = expand_recurrence(req.rule)
    if not items:
        raise HTTPException(status_code=400, detail="Keine Termine aus Regel erzeugt")

    created = 0
    skipped = 0

    for start_dt, end_dt, title, typ, notes in items:
        # Duplikat-Check: NUR nach Zeit (robust)
        exists = (
            db.query(Event)
            .filter(
                Event.user_id == user.id,
                Event.start_at == start_dt,
                Event.end_at == end_dt,
            )
            .first()
        )
        if exists:
            skipped += 1
            continue

        ev = Event(
            user_id=user.id,
            title=title,
            start_at=start_dt,
            end_at=end_dt,
            type=typ,
            notes=notes,
        )
        db.add(ev)
        created += 1

    db.commit()
    return {"ok": True, "created": created, "skipped_duplicates": skipped}

# ---------- Calendar Events (GET) ----------
class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    start_at: datetime
    end_at: datetime
    type: Optional[str] = None
    notes: Optional[str] = None


@app.get("/api/calendar/events", response_model=list[EventOut])
def calendar_events(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    from_date: date | None = Query(default=None),
    to_date: date | None = Query(default=None),
):
    q = db.query(Event).filter(Event.user_id == user.id)

    if from_date:
        q = q.filter(Event.start_at >= datetime.combine(from_date, time.min))
    if to_date:
        q = q.filter(Event.start_at <= datetime.combine(to_date, time.max))

    return q.order_by(Event.start_at.asc()).all()

@app.post("/api/calendar/deduplicate")
def calendar_deduplicate(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # alle Events dieses Users nach Zeit sortiert
    events = (
        db.query(Event)
        .filter(Event.user_id == user.id)
        .order_by(Event.start_at.asc(), Event.end_at.asc(), Event.id.asc())
        .all()
    )

    seen = set()
    removed = 0

    for ev in events:
        key = (ev.start_at, ev.end_at)  # Duplikat-Kriterium
        if key in seen:
            db.delete(ev)
            removed += 1
        else:
            seen.add(key)

    db.commit()
    return {"ok": True, "removed_duplicates": removed}
from datetime import datetime, date, time

@app.post("/api/calendar/sync")
def calendar_sync(
    req: SaveRecurrenceRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # 1) alles vor heute löschen (ab 00:00 heute bleibt)
    today_start = datetime.combine(date.today(), time.min)

    # WICHTIG: Wenn du nur Trainingsplan löschen willst, nimm zusätzlich Event.type == "training"
    deleted = (
        db.query(Event)
        .filter(
            Event.user_id == user.id,
            Event.start_at < today_start,
            # Optional, empfohlen:
            # Event.type == "training"
        )
        .delete(synchronize_session=False)
    )
    db.commit()

    # 2) neue Termine erzeugen und speichern (deine bestehende Logik)
    items = expand_recurrence(req.rule)
    if not items:
        raise HTTPException(status_code=400, detail="Keine Termine aus Regel erzeugt")

    created = 0
    skipped = 0

    for start_dt, end_dt, title, typ, notes in items:
        exists = (
            db.query(Event)
            .filter(
                Event.user_id == user.id,
                Event.start_at == start_dt,
                Event.end_at == end_dt,
            )
            .first()
        )
        if exists:
            skipped += 1
            continue

        db.add(Event(
            user_id=user.id,
            title=title,
            start_at=start_dt,
            end_at=end_dt,
            type=typ,
            notes=notes,
        ))
        created += 1

    db.commit()

    # 3) deduplicate (wie in /api/calendar/deduplicate)
    events = (
        db.query(Event)
        .filter(Event.user_id == user.id)
        .order_by(Event.start_at.asc(), Event.end_at.asc(), Event.id.asc())
        .all()
    )

    seen = set()
    removed = 0
    for ev in events:
        key = (ev.start_at, ev.end_at)
        if key in seen:
            db.delete(ev)
            removed += 1
        else:
            seen.add(key)

    db.commit()

    return {
        "ok": True,
        "deleted_past": deleted,
        "created": created,
        "skipped_duplicates": skipped,
        "removed_duplicates": removed,
    }










