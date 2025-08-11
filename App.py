import os, json, time, base64
from urllib.parse import urlencode
from flask import Flask, request, redirect, jsonify
import requests

app = Flask(__name__)

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI")
SCOPES = os.getenv(
    "GOOGLE_SCOPES",
    "https://mail.google.com/ https://www.googleapis.com/auth/calendar "
    "https://www.googleapis.com/auth/contacts https://www.googleapis.com/auth/contacts.other.readonly"
)
API_KEY = os.getenv("ACTION_API_KEY")

TOKENS_FILE = "tokens.json"

# ---------- helpers ----------
def _forbidden():
    return ("Forbidden", 403)

def _need_auth():
    return ("Not authorized. Open /auth/start first.", 401)

def require_api_key(req):
    return (API_KEY and req.headers.get("x-api-key") == API_KEY)

def load_tokens():
    if not os.path.exists(TOKENS_FILE): return None
    with open(TOKENS_FILE) as f: return json.load(f)

def save_tokens(d):
    with open(TOKENS_FILE, "w") as f: json.dump(d, f)

def refresh_access_token(refresh_token):
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    r = requests.post("https://oauth2.googleapis.com/token", data=data, timeout=20)
    r.raise_for_status()
    j = r.json()
    j["refresh_token"] = refresh_token
    j["expires_at"] = int(time.time()) + j.get("expires_in", 3500)
    save_tokens(j)
    return j

def get_access_token():
    t = load_tokens()
    if not t: return None
    if int(time.time()) >= t.get("expires_at", 0) - 60:
        t = refresh_access_token(t["refresh_token"])
    return t["access_token"]

# ---------- oauth ----------
@app.get("/auth/start")
def auth_start():
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "access_type": "offline",
        "prompt": "consent",
        "scope": SCOPES,
    }
    return redirect("https://accounts.google.com/o/oauth2/auth?" + urlencode(params))

@app.get("/auth/callback")
def auth_callback():
    code = request.args.get("code")
    if not code: return ("Missing code", 400)
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    r = requests.post("https://oauth2.googleapis.com/token", data=data, timeout=20)
    r.raise_for_status()
    j = r.json()
    j["expires_at"] = int(time.time()) + j.get("expires_in", 3500)
    save_tokens(j)
    return "Google account gekoppeld. Je kunt nu /gmail/unread, /calendar/events of /contacts/list testen."

# ---------- gmail ----------
@app.get("/gmail/unread")
def gmail_unread():
    if not require_api_key(request): return _forbidden()
    token = get_access_token()
    if not token: return _need_auth()
    q = request.args.get("q", "is:unread")
    max_results = request.args.get("maxResults", "10")
    url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params={"q": q, "maxResults": max_results}, timeout=20)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.get("/gmail/message")
def gmail_message():
    if not require_api_key(request): return _forbidden()
    token = get_access_token()
    if not token: return _need_auth()
    mid = request.args.get("id")
    if not mid: return ("Missing id", 400)
    url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params={"format": "full"}, timeout=20)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.post("/gmail/send")
def gmail_send():
    if not require_api_key(request): return _forbidden()
    token = get_access_token()
    if not token: return _need_auth()
    data = request.get_json(force=True)
    to = data.get("to"); subject = data.get("subject", ""); body = data.get("body", "")
    if not to: return ("Missing 'to'", 400)
    raw = f"To: {to}\r\nSubject: {subject}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{body}"
    b64 = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")
    url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
    r = requests.post(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json={"raw": b64}, timeout=20)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

# ---------- calendar ----------
@app.get("/calendar/events")
def cal_events():
    if not require_api_key(request): return _forbidden()
    token = get_access_token()
    if not token: return _need_auth()
    params = {
        "singleEvents": "true",
        "orderBy": "startTime",
        "timeMin": request.args.get("timeMin"),
        "timeMax": request.args.get("timeMax"),
        "maxResults": request.args.get("maxResults", "10"),
    }
    url = "https://www.googleapis.com/calendar/v3/calendars/primary/events"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params={k:v for k,v in params.items() if v}, timeout=20)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.post("/calendar/create")
def cal_create():
    if not require_api_key(request): return _forbidden()
    token = get_access_token()
    if not token: return _need_auth()
    data = request.get_json(force=True)
    event = {
        "summary": data.get("summary", "(no title)"),
        "start": {"dateTime": data["start"]},  # ISO 8601
        "end": {"dateTime": data["end"]},
    }
    if "attendees" in data:
        event["attendees"] = [{"email": e} for e in data["attendees"]]
    url = "https://www.googleapis.com/calendar/v3/calendars/primary/events"
    r = requests.post(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=event, timeout=20)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

# ---------- contacts (Google People API) ----------
BASE_PEOPLE = "https://people.googleapis.com/v1"

@app.get("/contacts/list")
def contacts_list():
    if not require_api_key(request): return _forbidden()
    token = get_access_token()
    if not token: return _need_auth()
    limit = int(request.args.get("limit", "50"))
    url = f"{BASE_PEOPLE}/people/me/connections"
    params = {"personFields": "names,emailAddresses,phoneNumbers,organizations", "pageSize": limit}
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=20)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.get("/contacts/search")
def contacts_search():
    if not require_api_key(request): return _forbidden()
    token = get_access_token()
    if not token: return _need_auth()
    q = request.args.get("q")
    if not q: return ("Missing q", 400)
    limit = int(request.args.get("limit", "25"))
    url = f"{BASE_PEOPLE}/people:searchContacts"
    params = {"query": q, "readMask": "names,emailAddresses,phoneNumbers,organizations", "pageSize": limit}
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=20)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.get("/contacts/get")
def contacts_get():
    if not require_api_key(request): return _forbidden()
    token = get_access_token()
    if not token: return _need_auth()
    rid = request.args.get("id")
    if not rid: return ("Missing id", 400)
    url = f"{BASE_PEOPLE}/{rid}"
    params = {"personFields": "names,emailAddresses,phoneNumbers,organizations"}
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=20)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.get("/")
def root():
    return jsonify({"ok": True, "endpoints": [
        "/auth/start",
        "/gmail/unread",
        "/gmail/message",
        "/gmail/send",
        "/calendar/events",
        "/calendar/create",
        "/contacts/list",
        "/contacts/search",
        "/contacts/get"
    ]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
