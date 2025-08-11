import os
import json
import time
import base64
from urllib.parse import urlencode

import requests
from flask import Flask, request, redirect, jsonify

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
app = Flask(__name__)

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "")
API_KEY = os.getenv("ACTION_API_KEY", "")

# Standaardscopes, overschrijf met GOOGLE_SCOPES (komma-gescheiden of spatie)
DEFAULT_SCOPES = [
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/contacts.other.readonly",
]
_scopes_env = os.getenv("GOOGLE_SCOPES", "")
if _scopes_env.strip():
    # mag komma of spatiegescheiden zijn
    SCOPES = [s.strip() for s in _scopes_env.replace(",", " ").split() if s.strip()]
else:
    SCOPES = DEFAULT_SCOPES

# Tokens persistent opslaan — bij voorkeur op /data (Render Disk)
TOKENS_FILE = "/data/tokens.json" if os.path.isdir("/data") else "tokens.json"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _forbidden():
    return jsonify({"error": "Forbidden"}), 403

def require_api_key(func):
    def wrapper(*args, **kwargs):
        if API_KEY:
            given = request.headers.get("x-api-key", "")
            if given != API_KEY:
                return _forbidden()
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def load_tokens():
    if not os.path.exists(TOKENS_FILE):
        return {}
    try:
        with open(TOKENS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_tokens(data):
    os.makedirs(os.path.dirname(TOKENS_FILE) or ".", exist_ok=True)
    with open(TOKENS_FILE, "w") as f:
        json.dump(data, f)

def _need_auth():
    return jsonify({"error": "Not authorized. Open /auth/start first."}), 401

def _hdr(headers, name, default=""):
    for h in headers or []:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", default)
    return default

def _exchange_code_for_tokens(code):
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    r = requests.post("https://oauth2.googleapis.com/token", data=data, timeout=30)
    r.raise_for_status()
    token_json = r.json()
    # Bewaar ook vervaltijd
    expires_at = int(time.time()) + int(token_json.get("expires_in", 3600)) - 60
    token_json["expires_at"] = expires_at
    return token_json

def _refresh_access_token(refresh_token):
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    r = requests.post("https://oauth2.googleapis.com/token", data=data, timeout=30)
    r.raise_for_status()
    token_json = r.json()
    token_json["refresh_token"] = refresh_token  # Google stuurt 'm soms niet terug
    token_json["expires_at"] = int(time.time()) + int(token_json.get("expires_in", 3600)) - 60
    return token_json

def _google_headers():
    tokens = load_tokens()
    if not tokens:
        return None
    # refresh indien nodig
    if int(tokens.get("expires_at", 0)) <= int(time.time()):
        if not tokens.get("refresh_token"):
            return None
        try:
            tokens = _refresh_access_token(tokens["refresh_token"])
            save_tokens(tokens)
        except Exception:
            return None
    access_token = tokens.get("access_token")
    if not access_token:
        return None
    return {"Authorization": f"Bearer {access_token}"}

# -----------------------------------------------------------------------------
# Health
# -----------------------------------------------------------------------------
@app.get("/")
def ping():
    return jsonify({
        "ok": True,
        "endpoints": [
            "/auth/start",
            "/gmail/unread",
            "/gmail/message",
            "/gmail/send",
            "/gmail/unread_detail",
            "/gmail/reply",
            "/gmail/mark_read",
            "/gmail/archive",
            "/calendar/events",
            "/calendar/create",
            "/contacts/list",
            "/contacts/search",
            "/contacts/get",
        ]
    })

# -----------------------------------------------------------------------------
# OAuth
# -----------------------------------------------------------------------------
@app.get("/auth/start")
@require_api_key
def auth_start():
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",  # forceer refresh_token
        "include_granted_scopes": "true",
    }
    url = f"https://accounts.google.com/o/oauth2/auth?{urlencode(params)}"
    return redirect(url, code=302)

@app.get("/auth/callback")
def auth_callback():
    code = request.args.get("code")
    if not code:
        return "Missing code", 400
    try:
        tokens = _exchange_code_for_tokens(code)
        save_tokens(tokens)
        return "Google account gekoppeld. Je kunt nu /gmail/unread, /calendar/events of /contacts/list testen."
    except Exception as e:
        return f"Error exchanging code: {e}", 400

# -----------------------------------------------------------------------------
# Gmail
# -----------------------------------------------------------------------------
@app.get("/gmail/unread")
@require_api_key
def gmail_unread():
    headers = _google_headers()
    if not headers:
        return _need_auth()
    q = request.args.get("q", "is:unread")
    max_results = request.args.get("maxResults", "10")
    r = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        headers=headers,
        params={"q": q, "maxResults": max_results},
        timeout=30,
    )
    if r.status_code == 401:  # probeer één keer refresh
        tokens = load_tokens()
        if tokens.get("refresh_token"):
            try:
                save_tokens(_refresh_access_token(tokens["refresh_token"]))
                headers = _google_headers()
                r = requests.get(
                    "https://gmail.googleapis.com/gmail/v1/users/me/messages",
                    headers=headers,
                    params={"q": q, "maxResults": max_results},
                    timeout=30,
                )
            except Exception:
                pass
    return r.json(), r.status_code

@app.get("/gmail/message")
@require_api_key
def gmail_message():
    headers = _google_headers()
    if not headers:
        return _need_auth()
    mid = request.args.get("id")
    if not mid:
        return {"error": "id required"}, 400
    r = requests.get(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}",
        headers=headers,
        params={"format": "full"},
        timeout=30,
    )
    return r.json(), r.status_code

@app.post("/gmail/send")
@require_api_key
def gmail_send():
    headers = _google_headers()
    if not headers:
        return _need_auth()
    data = request.get_json(force=True, silent=True) or {}
    to = data.get("to")
    subject = data.get("subject", "")
    body = data.get("body", "")
    if not to:
        return {"error": "to required"}, 400
    raw = (
        f"To: {to}\r\n"
        f"Subject: {subject}\r\n"
        f"Content-Type: text/plain; charset=UTF-8\r\n"
        f"\r\n"
        f"{body}\r\n"
    )
    b64 = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("utf-8")
    r = requests.post(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        headers={**headers, "Content-Type": "application/json"},
        json={"raw": b64},
        timeout=30,
    )
    return r.json(), r.status_code

# --- NIEUW: in één call details van ongelezen mails --------------------------------
@app.get("/gmail/unread_detail")
@require_api_key
def gmail_unread_detail():
    headers = _google_headers()
    if not headers:
        return _need_auth()
    q = request.args.get("q", "is:unread")
    max_results = request.args.get("maxResults", "10")

    lst = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        headers=headers,
        params={"q": q, "maxResults": max_results},
        timeout=30,
    ).json()

    out = []
    for m in lst.get("messages", []):
        mid = m["id"]
        full = requests.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}",
            headers=headers,
            params={"format": "full"},
            timeout=30,
        ).json()
        hdrs = full.get("payload", {}).get("headers", [])
        out.append({
            "id": mid,
            "threadId": full.get("threadId"),
            "from": _hdr(hdrs, "From"),
            "to": _hdr(hdrs, "To"),
            "subject": _hdr(hdrs, "Subject"),
            "date": _hdr(hdrs, "Date"),
            "snippet": full.get("snippet", "")
        })
    return {"messages": out}

# --- NIEUW: reply --------------------------------------------------------------
@app.post("/gmail/reply")
@require_api_key
def gmail_reply():
    headers = _google_headers()
    if not headers:
        return _need_auth()
    data = request.get_json(force=True, silent=True) or {}
    msg_id = data.get("id")
    body = data.get("body", "")
    to_override = data.get("to")
    subject_override = data.get("subject")
    if not msg_id or not body:
        return {"error": "id and body are required"}, 400

    orig = requests.get(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}",
        headers=headers,
        params={"format": "full"},
        timeout=30,
    ).json()
    thread_id = orig.get("threadId")
    oh = orig.get("payload", {}).get("headers", [])
    orig_from = _hdr(oh, "From")
    orig_to = _hdr(oh, "To")
    orig_subject = _hdr(oh, "Subject")
    orig_message_id = _hdr(oh, "Message-ID")

    to = to_override or orig_from or orig_to
    subject = subject_override or (f"Re: {orig_subject}" if orig_subject else "Re:")

    raw = (
        f"To: {to}\r\n"
        f"Subject: {subject}\r\n"
        f"In-Reply-To: {orig_message_id}\r\n"
        f"References: {orig_message_id}\r\n"
        f"Content-Type: text/plain; charset=UTF-8\r\n"
        f"\r\n"
        f"{body}\r\n"
    )
    b64 = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("utf-8")
    payload = {"raw": b64}
    if thread_id:
        payload["threadId"] = thread_id

    r = requests.post(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        headers={**headers, "Content-Type": "application/json"},
        json=payload,
        timeout=30,
    )
    return r.json(), r.status_code

# --- NIEUW: mark as read -------------------------------------------------------
@app.post("/gmail/mark_read")
@require_api_key
def gmail_mark_read():
    headers = _google_headers()
    if not headers:
        return _need_auth()
    data = request.get_json(force=True, silent=True) or {}
    msg_id = data.get("id")
    if not msg_id:
        return {"error": "id required"}, 400
    r = requests.post(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}/modify",
        headers={**headers, "Content-Type": "application/json"},
        json={"removeLabelIds": ["UNREAD"]},
        timeout=30,
    )
    return r.json(), r.status_code

# --- NIEUW: archive (verwijder INBOX) -----------------------------------------
@app.post("/gmail/archive")
@require_api_key
def gmail_archive():
    headers = _google_headers()
    if not headers:
        return _need_auth()
    data = request.get_json(force=True, silent=True) or {}
    msg_id = data.get("id")
    if not msg_id:
        return {"error": "id required"}, 400
    r = requests.post(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}/modify",
        headers={**headers, "Content-Type": "application/json"},
        json={"removeLabelIds": ["INBOX"]},
        timeout=30,
    )
    return r.json(), r.status_code

# -----------------------------------------------------------------------------
# Calendar
# -----------------------------------------------------------------------------
@app.get("/calendar/events")
@require_api_key
def calendar_events():
    headers = _google_headers()
    if not headers:
        return _need_auth()
    params = {}
    if "timeMin" in request.args:
        params["timeMin"] = request.args["timeMin"]
    if "timeMax" in request.args:
        params["timeMax"] = request.args["timeMax"]
    if "maxResults" in request.args:
        params["maxResults"] = request.args["maxResults"]
    r = requests.get(
        "https://www.googleapis.com/calendar/v3/calendars/primary/events",
        headers=headers,
        params=params,
        timeout=30,
    )
    return r.json(), r.status_code

@app.post("/calendar/create")
@require_api_key
def calendar_create():
    headers = _google_headers()
    if not headers:
        return _need_auth()
    data = request.get_json(force=True, silent=True) or {}
    summary = data.get("summary")
    start = data.get("start")
    end = data.get("end")
    attendees = data.get("attendees", [])
    if not summary or not start or not end:
        return {"error": "summary, start, end required"}, 400
    payload = {
        "summary": summary,
        "start": {"dateTime": start},
        "end": {"dateTime": end},
    }
    if attendees:
        payload["attendees"] = [{"email": a} for a in attendees]
    r = requests.post(
        "https://www.googleapis.com/calendar/v3/calendars/primary/events",
        headers={**headers, "Content-Type": "application/json"},
        json=payload,
        timeout=30,
    )
    return r.json(), r.status_code

# -----------------------------------------------------------------------------
# Contacts
# -----------------------------------------------------------------------------
@app.get("/contacts/list")
@require_api_key
def contacts_list():
    headers = _google_headers()
    if not headers:
        return _need_auth()
    limit = int(request.args.get("limit", "50"))
    r = requests.get(
        "https://people.googleapis.com/v1/otherContacts",
        headers=headers,
        params={"pageSize": limit, "readMask": "names,emailAddresses,phoneNumbers"},
        timeout=30,
    )
    return r.json(), r.status_code

@app.get("/contacts/search")
@require_api_key
def contacts_search():
    headers = _google_headers()
    if not headers:
        return _need_auth()
    q = request.args.get("q")
    if not q:
        return {"error": "q required"}, 400
    limit = int(request.args.get("limit", "25"))
    r = requests.get(
        "https://people.googleapis.com/v1/otherContacts:search",
        headers=headers,
        params={"query": q, "pageSize": limit, "readMask": "names,emailAddresses,phoneNumbers"},
        timeout=30,
    )
    return r.json(), r.status_code

@app.get("/contacts/get")
@require_api_key
def contacts_get():
    headers = _google_headers()
    if not headers:
        return _need_auth()
    rid = request.args.get("id")
    if not rid:
        return {"error": "id required"}, 400
    r = requests.get(
        f"https://people.googleapis.com/v1/{rid}",
        headers=headers,
        params={"readMask": "names,emailAddresses,phoneNumbers"},
        timeout=30,
    )
    return r.json(), r.status_code

# -----------------------------------------------------------------------------
# Gunicorn entry
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
