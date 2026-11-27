import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlparse

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from db import Store

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("chat")

BASE_DIR = Path(__file__).parent

# only accept small base64 image data URLs as profile photos
PHOTO_RE = re.compile(r"data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}")
USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{3,20}")
# GIFs may only point at GIPHY's image servers (no query string, no quotes, no "..")
GIPHY_URL_RE = re.compile(r"https://(media[0-9]?|i)\.giphy\.com/media/[A-Za-z0-9._/-]{1,300}\.(gif|webp)")
# stickers are animated Noto emoji, identified by their code points, e.g. "1f602" or "2764_fe0f"
STICKER_RE = re.compile(r"[0-9a-f]{4,5}(_[0-9a-f]{4,5}){0,3}")
GIPHY_API_KEY = os.environ.get("GIPHY_API_KEY", "").strip()


def _int_between(value, default: int, low: int = 1, high: int = 1000) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


def media_fields(kind: str, media: str | None) -> dict:
    """Extra message fields for GIF/sticker messages, rebuilt from the stored `media` column."""
    if kind == "gif" and media:
        try:
            return {"gif": json.loads(media)}
        except ValueError:
            return {}
    if kind == "sticker" and media:
        return {"sticker": media}
    return {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------- passwords
# scrypt (memory-hard) with OWASP-recommended parameters: N=2^14, r=8, p=5 (~16 MB)
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 5


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                        maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, expected = stored.split("$")
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                            maxmem=64 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(expected))
    except (ValueError, TypeError):
        return False


# used when a username doesn't exist, so a failed login takes the same time either way
DUMMY_HASH = hash_password(secrets.token_hex(8))

# ---------------------------------------------------------------- login rate limit
MAX_FAILS, FAIL_WINDOW = 10, 15 * 60
_fails: dict[str, deque] = {}


def _too_many(key: str) -> bool:
    q = _fails.get(key)
    if not q:
        return False
    cutoff = time.monotonic() - FAIL_WINDOW
    while q and q[0] < cutoff:
        q.popleft()
    return len(q) >= MAX_FAILS


def _record_fail(key: str):
    _fails.setdefault(key, deque()).append(time.monotonic())


# ---------------------------------------------------------------- sessions
COOKIE = "session"
SESSION_DAYS = 30


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def start_session(request: Request, response: Response, username: str):
    token = secrets.token_urlsafe(32)
    await store.run(store.create_session, _token_hash(token), username, now())
    https = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
    response.set_cookie(COOKIE, token, max_age=SESSION_DAYS * 86400, httponly=True,
                        samesite="lax", secure=https, path="/")


async def session_user(token: str | None) -> str | None:
    if not token:
        return None
    row = await store.run(store.get_session, _token_hash(token))
    if not row:
        return None
    if datetime.now(timezone.utc) - datetime.fromisoformat(row["created"]) > timedelta(days=SESSION_DAYS):
        await store.run(store.delete_session, _token_hash(token))
        return None
    return row["username"] if row["username"] in manager.known else None


# ---------------------------------------------------------------- chat state
class ChatManager:
    """Chat state lives in memory for speed; every change is also saved to the database."""

    MAX_PHOTO = 200_000  # characters of data URL (~150 KB image)
    MAX_BIO = 160

    def __init__(self, db: Store):
        self.db = db
        self.connections: dict[str, set[WebSocket]] = {}
        self.known: set[str] = set()
        self.friends: set[frozenset] = set()
        self.requests: set[tuple[str, str]] = set()  # (from, to)
        self.messages: list[dict] = []
        self.last_seen: dict[str, str] = {}  # user -> ISO time they went offline
        self.next_id = 1
        self.profiles: dict[str, dict] = {}  # user -> {"bio", "photo", "joined"}
        self.follows: set[tuple[str, str]] = set()  # (follower, followee)

    def load(self, data: dict):
        for u in data["users"]:
            name = u["username"]
            self.known.add(name)
            self.profiles[name] = {"bio": u["bio"] or "", "photo": u["photo"], "joined": u["joined"]}
            if u["last_seen"]:
                self.last_seen[name] = u["last_seen"]
        self.friends = {frozenset((r["a"], r["b"])) for r in data["friends"]}
        self.requests = {(r["sender"], r["receiver"]) for r in data["requests"]}
        self.follows = {(r["follower"], r["followee"]) for r in data["follows"]}
        self.messages = [{"type": "message", "id": m["id"], "from": m["sender"], "to": m["receiver"],
                          "text": m["text"], "ts": m["ts"], "status": m["status"],
                          "kind": m.get("kind") or "text", **media_fields(m.get("kind") or "text", m.get("media"))}
                         for m in data["messages"]]
        self.next_id = max((m["id"] for m in self.messages), default=0) + 1

    async def add_user(self, name: str, joined: str):
        self.known.add(name)
        self.profiles[name] = {"bio": "", "photo": None, "joined": joined}
        await self.push_state()  # others see the new person in "Find people"

    # ----- friendship helpers that also save to the database
    def _add_friend(self, a, b):
        self.friends.add(frozenset((a, b)))
        self.db.add_pair("friends", *sorted((a, b)))

    def _remove_friend(self, a, b):
        self.friends.discard(frozenset((a, b)))
        self.db.remove_pair("friends", *sorted((a, b)))

    def _add_follow(self, a, b):
        if (a, b) not in self.follows:
            self.follows.add((a, b))
            self.db.add_pair("follows", a, b)

    def _remove_follow(self, a, b):
        self.follows.discard((a, b))
        self.db.remove_pair("follows", a, b)

    def _add_request(self, a, b):
        self.requests.add((a, b))
        self.db.add_pair("requests", a, b)

    def _remove_request(self, a, b):
        self.requests.discard((a, b))
        self.db.remove_pair("requests", a, b)

    def _set_status(self, msgs: list[dict], status: str):
        for m in msgs:
            m["status"] = status
        if msgs:
            self.db.set_status([m["id"] for m in msgs], status)

    # ----- read helpers
    def profile_of(self, user: str) -> dict:
        return self.profiles.setdefault(user, {"bio": "", "photo": None, "joined": now()})

    def followers(self, user: str) -> list[str]:
        return sorted((a for a, b in self.follows if b == user), key=str.lower)

    def following(self, user: str) -> list[str]:
        return sorted((b for a, b in self.follows if a == user), key=str.lower)

    def friends_of(self, user: str) -> list[str]:
        return sorted((next(iter(p - {user})) for p in self.friends if user in p), key=str.lower)

    def relation(self, me: str, other: str) -> str:
        if frozenset((me, other)) in self.friends:
            return "friend"
        if (me, other) in self.requests:
            return "sent"
        if (other, me) in self.requests:
            return "received"
        return "none"

    def profile_payload(self, viewer: str, user: str) -> dict:
        p = self.profile_of(user)
        return {
            "type": "profile", "name": user, "bio": p["bio"], "photo": p["photo"], "joined": p["joined"],
            "online": user in self.connections, "last_seen": self.last_seen.get(user),
            "followers": self.followers(user), "following": self.following(user),
            "friends": self.friends_of(user),
            "relation": "self" if viewer == user else self.relation(viewer, user),
            "i_follow": (viewer, user) in self.follows, "follows_me": (user, viewer) in self.follows,
            "my_following": self.following(viewer),  # lets the lists show Follow/Unfollow per person
        }

    def state_for(self, me: str) -> dict:
        users = [
            {"name": u, "online": u in self.connections, "relation": self.relation(me, u),
             "last_seen": self.last_seen.get(u), "photo": self.profile_of(u)["photo"]}
            for u in sorted(self.known, key=str.lower)
            if u != me
        ]
        return {"type": "state", "users": users, "me": {"photo": self.profile_of(me)["photo"]}}

    # ----- sending
    async def send(self, user: str, payload: dict):
        data = json.dumps(payload)
        for ws in list(self.connections.get(user, ())):
            try:
                await ws.send_text(data)
            except Exception:
                self.connections[user].discard(ws)

    async def push_state(self):
        for user in list(self.connections):
            await self.send(user, self.state_for(user))

    async def send_receipts(self, updated: list[dict], status: str):
        """Tell each sender which of their messages changed status."""
        by_sender: dict[str, list[int]] = {}
        for m in updated:
            by_sender.setdefault(m["from"], []).append(m["id"])
        for sender, ids in by_sender.items():
            await self.send(sender, {"type": "receipt", "ids": ids, "status": status})

    # ----- connection lifecycle
    async def join(self, user: str, ws: WebSocket):
        await ws.accept()
        self.connections.setdefault(user, set()).add(ws)
        # messages sent while this user was offline are delivered now
        delivered = [m for m in self.messages if m["to"] == user and m["status"] == "sent"]
        self._set_status(delivered, "delivered")
        mine = [m for m in self.messages if user in (m["from"], m["to"])]
        await ws.send_text(json.dumps({"type": "history", "messages": mine}))
        await self.send_receipts(delivered, "delivered")
        await self.push_state()

    async def leave(self, user: str, ws: WebSocket):
        conns = self.connections.get(user, set())
        conns.discard(ws)
        if not conns:
            self.connections.pop(user, None)
            self.last_seen[user] = now()
            self.db.save_last_seen(user, self.last_seen[user])
        await self.push_state()

    # ----- actions from the browser
    async def handle(self, me: str, data: dict):
        action = data.get("action")
        to = str(data.get("to", ""))

        if action == "profile_update":
            p = self.profile_of(me)
            if "bio" in data:
                p["bio"] = str(data.get("bio") or "").strip()[: self.MAX_BIO]
            if "photo" in data:
                photo = data.get("photo")
                if photo is None:
                    p["photo"] = None
                elif isinstance(photo, str) and len(photo) <= self.MAX_PHOTO and PHOTO_RE.fullmatch(photo):
                    p["photo"] = photo
            self.db.save_profile(me, p["bio"], p["photo"])
            await self.send(me, self.profile_payload(me, me))
            await self.push_state()  # everyone sees the new photo
            return
        if action == "get_profile":
            if to in self.known:
                await self.send(me, self.profile_payload(me, to))
            return

        if to not in self.known or to == me:
            return
        rel = self.relation(me, to)

        if action in ("follow", "unfollow"):
            if action == "follow" and (me, to) not in self.follows:
                self._add_follow(me, to)
                await self.send(to, {"type": "notice", "text": f"{me} started following you"})
            elif action == "unfollow":
                self._remove_follow(me, to)
                if rel == "friend":
                    # unfollowing a friend also ends the friendship (no more chat/calls)
                    self._remove_friend(me, to)
            await self.send(me, self.profile_payload(me, to))
            await self.push_state()
            return
        if action == "request" and rel == "none":
            self._add_request(me, to)
        elif action == "accept" and rel == "received":
            self._remove_request(to, me)
            self._add_friend(me, to)
            # friends follow each other automatically
            self._add_follow(me, to)
            self._add_follow(to, me)
            await self.send(to, {"type": "notice", "text": f"{me} accepted your friend request"})
        elif action == "decline" and rel == "received":
            self._remove_request(to, me)
        elif action == "cancel" and rel == "sent":
            self._remove_request(me, to)
        elif action == "signal" and rel == "friend":
            # WebRTC call signaling (offer/answer/ice/end/reject), relayed as-is, never stored
            payload = data.get("data")
            if not isinstance(payload, dict):
                return
            if to in self.connections:
                await self.send(to, {"type": "signal", "from": me, "data": payload})
            elif payload.get("kind") == "offer":
                await self.send(me, {"type": "signal", "from": to, "data": {"kind": "unavailable"}})
            return
        elif action == "message" and rel == "friend":
            kind = data.get("kind") or "text"
            media, extra = None, {}
            if kind == "text":
                text = str(data.get("text", "")).strip()[:2000]
                if not text:
                    return
            elif kind == "gif":
                g = data.get("gif") if isinstance(data.get("gif"), dict) else {}
                url = str(g.get("url", ""))
                if not GIPHY_URL_RE.fullmatch(url) or ".." in url:
                    return
                gif = {"url": url, "w": _int_between(g.get("w"), 200), "h": _int_between(g.get("h"), 200)}
                text, media, extra = "GIF", json.dumps(gif), {"gif": gif}
            elif kind == "sticker":
                code = str(data.get("sticker", ""))
                if not STICKER_RE.fullmatch(code):
                    return
                text, media, extra = "Sticker", code, {"sticker": code}
            else:
                return
            msg = {"type": "message", "id": self.next_id, "from": me, "to": to, "text": text,
                   "ts": now(), "status": "delivered" if to in self.connections else "sent",
                   "kind": kind, **extra}
            self.next_id += 1
            self.messages.append(msg)
            self.db.add_message(msg, media)
            await self.send(me, msg)
            await self.send(to, msg)
            return
        elif action == "seen" and rel == "friend":
            # `me` has read everything `to` sent them
            seen = [m for m in self.messages if m["from"] == to and m["to"] == me and m["status"] != "seen"]
            self._set_status(seen, "seen")
            await self.send_receipts(seen, "seen")
            return
        else:
            return
        await self.push_state()


store = Store()
manager = ChatManager(store)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await store.run(store.init)
    manager.load(await store.run(store.load_all))
    log.info("database: %s, %d users, %d messages loaded", store.kind, len(manager.known), len(manager.messages))
    yield
    store.close()


app = FastAPI(lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/")
async def index():
    return FileResponse(BASE_DIR / "static" / "index.html")


# ---------------------------------------------------------------- auth API
class Credentials(BaseModel):
    username: str
    password: str


@app.post("/api/signup")
async def signup(creds: Credentials, request: Request, response: Response):
    username = creds.username.strip()
    if not USERNAME_RE.fullmatch(username):
        raise HTTPException(400, "Username must be 3–20 characters: letters, numbers, . _ or -")
    if not 8 <= len(creds.password) <= 128:
        raise HTTPException(400, "Password must be at least 8 characters")
    pw_hash = await run_in_threadpool(hash_password, creds.password)
    joined = now()
    if not await store.run(store.create_user, username, pw_hash, joined):
        raise HTTPException(409, "That username is already taken")
    await manager.add_user(username, joined)
    await start_session(request, response, username)
    return {"username": username}


@app.post("/api/login")
async def login(creds: Credentials, request: Request, response: Response):
    key = creds.username.strip().lower()
    if _too_many(key):
        raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")
    row = await store.run(store.get_login, creds.username.strip())
    ok = await run_in_threadpool(verify_password, creds.password[:128], row["pw_hash"] if row else DUMMY_HASH)
    if not row or not ok:
        _record_fail(key)
        raise HTTPException(401, "Wrong username or password")
    _fails.pop(key, None)
    await start_session(request, response, row["username"])
    return {"username": row["username"]}


@app.get("/api/me")
async def me(request: Request):
    user = await session_user(request.cookies.get(COOKIE))
    if not user:
        raise HTTPException(401, "Not signed in")
    return {"username": user}


@app.post("/api/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    if token:
        await store.run(store.delete_session, _token_hash(token))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


# ---------------------------------------------------------------- GIF search (GIPHY)
# The free GIPHY beta key allows 100 calls per hour, so results are cached and each
# user is limited. The key stays on the server; browsers only get image URLs.
GIF_CACHE_SECONDS = 15 * 60
GIF_USER_LIMIT, GIF_USER_WINDOW = 20, 60
_gif_cache: dict[tuple[str, int], tuple[float, list]] = {}
_gif_calls: dict[str, deque] = {}


def _no_query(url: str | None) -> str:
    return (url or "").split("?", 1)[0]


def _giphy_fetch(q: str, offset: int) -> list[dict]:
    params = {"api_key": GIPHY_API_KEY, "limit": 24, "offset": offset, "rating": "pg"}
    if q:
        params.update(q=q, lang="en")
    url = f"https://api.giphy.com/v1/gifs/{'search' if q else 'trending'}?{urlencode(params)}"
    with urllib.request.urlopen(url, timeout=10) as r:
        data = json.load(r)
    results = []
    for g in data.get("data", []):
        images = g.get("images") or {}
        full = images.get("fixed_height") or {}
        small = images.get("fixed_height_small") or full
        src = _no_query(full.get("webp") or full.get("url"))
        preview = _no_query(small.get("webp") or small.get("url"))
        if not (GIPHY_URL_RE.fullmatch(src) and GIPHY_URL_RE.fullmatch(preview)):
            continue
        results.append({"url": src, "preview": preview,
                        "w": _int_between(full.get("width"), 200), "h": _int_between(full.get("height"), 200),
                        "title": str(g.get("title") or "GIF")[:80]})
    return results


@app.get("/api/gifs")
async def gifs(request: Request, q: str = "", offset: int = 0):
    user = await session_user(request.cookies.get(COOKIE))
    if not user:
        raise HTTPException(401, "Not signed in")
    if not GIPHY_API_KEY:
        raise HTTPException(503, "GIF search isn't set up on this server yet")
    q, offset = q.strip()[:50], max(0, min(offset, 4999))
    key = (q.lower(), offset)
    hit = _gif_cache.get(key)
    if hit and time.monotonic() - hit[0] < GIF_CACHE_SECONDS:
        return {"results": hit[1]}

    calls = _gif_calls.setdefault(user, deque())
    cutoff = time.monotonic() - GIF_USER_WINDOW
    while calls and calls[0] < cutoff:
        calls.popleft()
    if len(calls) >= GIF_USER_LIMIT:
        raise HTTPException(429, "Too many GIF searches. Wait a minute and try again.")
    calls.append(time.monotonic())

    try:
        results = await run_in_threadpool(_giphy_fetch, q, offset)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise HTTPException(429, "GIF search limit reached for this hour. Try again later.")
        log.warning("GIPHY returned HTTP %s", e.code)
        raise HTTPException(502, "GIF search is unavailable right now")
    except Exception as e:  # network errors, bad JSON
        log.warning("GIPHY request failed: %s", type(e).__name__)
        raise HTTPException(502, "GIF search is unavailable right now")
    if len(_gif_cache) > 300:
        _gif_cache.clear()
    _gif_cache[key] = (time.monotonic(), results)
    return {"results": results}


# ---------------------------------------------------------------- live connection
@app.websocket("/ws")
async def chat(ws: WebSocket):
    # only allow connections from this site's own pages
    origin = ws.headers.get("origin")
    hosts = {ws.headers.get("host"), ws.headers.get("x-forwarded-host")}
    if origin and urlparse(origin).netloc not in hosts:
        await ws.close(code=1008)
        return
    user = await session_user(ws.cookies.get(COOKIE))
    if not user:
        await ws.accept()
        await ws.close(code=4401)  # tells the page to show the sign-in screen
        return
    await manager.join(user, ws)
    try:
        while True:
            try:
                data = json.loads(await ws.receive_text())
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                await manager.handle(user, data)
    except WebSocketDisconnect:
        await manager.leave(user, ws)
