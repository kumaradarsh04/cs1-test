"""Backend for the test platform.  Run:  python -m uvicorn main:app --reload --port 8000
Env vars: GOOGLE_CLIENT_ID, DATABASE_URL, [ADMIN_PASSWORD], [ALLOWED_ORIGINS]
"""
import os, hmac
import psycopg2
from psycopg2.extras import Json
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google.oauth2 import id_token
from google.auth.transport import requests as greq

from dotenv import load_dotenv

load_dotenv()  # load .env file if present

CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
DATABASE_URL = os.environ["DATABASE_URL"]
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "I_WILL")
DOMAIN = "@indoreinstitute.com"

# Correct option (1-4) for each question, in the same order as QUESTIONS in index.html.
# Kept on the server so students can't read answers from the page source.
ANSWERS = [1, 2, 2]
TOTAL = len(ANSWERS)

app = FastAPI()
app.add_middleware(CORSMiddleware,
                   allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
                   allow_methods=["*"], allow_headers=["*"])

UPSERT = """
insert into results (email, name, answers, score, total_attempted, updated_at)
values (%s, %s, %s, %s, %s, now())
on conflict (email) do update set
  name = excluded.name, answers = excluded.answers, score = excluded.score,
  total_attempted = excluded.total_attempted, updated_at = now()
"""


def connect():
    return psycopg2.connect(DATABASE_URL, connect_timeout=10)


def verify(authorization: str):
    """Validate the Google ID token and enforce the domain rule."""
    try:
        info = id_token.verify_oauth2_token(
            authorization.removeprefix("Bearer "), greq.Request(), CLIENT_ID)
    except Exception:
        raise HTTPException(401, "Invalid or expired sign-in. Please sign in again.")
    email = info.get("email", "").lower()
    if not info.get("email_verified") or not email.endswith(DOMAIN):
        raise HTTPException(403, f"Only {DOMAIN} accounts can take this test.")
    return email, info.get("name", email)


@app.post("/auth")
def auth(authorization: str = Header(...)):
    email, name = verify(authorization)
    with connect() as conn, conn.cursor() as cur:
        cur.execute("select answers from results where email = %s", (email,))
        row = cur.fetchone()
        answers = row[0] if row else {}
        if not row:  # first visit -> create the row
            cur.execute(UPSERT, (email, name, Json({}), f"0/{TOTAL}", f"0/{TOTAL}"))
    return {"name": name, "email": email, "total": TOTAL, "answers": answers}


class Answer(BaseModel):
    q: int
    choice: int


@app.post("/answer")
def answer(body: Answer, authorization: str = Header(...)):
    email, name = verify(authorization)
    if not (0 <= body.q < TOTAL and 1 <= body.choice <= 4):
        raise HTTPException(400, "Bad question or option.")
    with connect() as conn, conn.cursor() as cur:
        cur.execute("select answers from results where email = %s for update", (email,))
        row = cur.fetchone()
        answers = row[0] if row else {}
        answers[str(body.q)] = body.choice      # re-answering overwrites, never double counts
        correct = sum(1 for k, v in answers.items() if ANSWERS[int(k)] == v)
        cur.execute(UPSERT, (email, name, Json(answers),
                             f"{correct}/{TOTAL}", f"{len(answers)}/{TOTAL}"))
    return {"ok": True, "attempted": len(answers)}


@app.get("/admin/results")
def admin_results(x_admin_password: str = Header("")):
    if not hmac.compare_digest(x_admin_password, ADMIN_PASSWORD):
        raise HTTPException(401, "Wrong password.")
    with connect() as conn, conn.cursor() as cur:
        cur.execute("select name, score, total_attempted from results order by name")
        return [{"name": n, "score": s, "total_attempted": t} for n, s, t in cur.fetchall()]