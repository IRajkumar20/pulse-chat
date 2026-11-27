import json
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).parent
app = FastAPI()
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# only accept small base64 image data URLs as profile photos
PHOTO_RE = re.compile(r"data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}")


class ChatManager:
    """One-to-one chat with friend requests. Everything is kept in memory."""

    def __init__(self):
        self.connections: dict[str, set[WebSocket]] = {}
        self.known: set[str] = set()
        self.friends: set[frozenset] = set()
        self.requests: set[tuple[str, str]] = set()  # (from, to)
        self.messages: list[dict] = []
        self.last_seen: dict[str, str] = {}  # user -> ISO time they went offline
        self.next_id = 1
        self.profiles: dict[str, dict] = {}  # user -> {"bio", "photo", "joined"}
        self.follows: set[tuple[str, str]] = set()  # (follower, followee)

    MAX_PHOTO = 200_000  # characters of data URL (~150 KB image)
    MAX_BIO = 160

    def profile_of(self, user: str) -> dict:
        return self.profiles.setdefault(user, {"bio": "", "photo": None, "joined": self.now()})

    def followers(self, user: str) -> list[str]:
        return sorted((a for a, b in self.follows if b == user), key=str.lower)

    def following(self, user: str) -> list[str]:
        return sorted((b for a, b in self.follows if a == user), key=str.lower)

    def friends_of(self, user: str) -> list[str]:
        return sorted((next(iter(p - {user})) for p in self.friends if user in p), key=str.lower)

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

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()

    async def send_receipts(self, updated: list[dict], status: str):
        """Tell each sender which of their messages changed status."""
        by_sender: dict[str, list[int]] = {}
        for m in updated:
            by_sender.setdefault(m["from"], []).append(m["id"])
        for sender, ids in by_sender.items():
            await self.send(sender, {"type": "receipt", "ids": ids, "status": status})

    def relation(self, me: str, other: str) -> str:
        if frozenset((me, other)) in self.friends:
            return "friend"
        if (me, other) in self.requests:
            return "sent"
        if (other, me) in self.requests:
            return "received"
        return "none"

    def state_for(self, me: str) -> dict:
        users = [
            {"name": u, "online": u in self.connections, "relation": self.relation(me, u),
             "last_seen": self.last_seen.get(u), "photo": self.profile_of(u)["photo"]}
            for u in sorted(self.known, key=str.lower)
            if u != me
        ]
        return {"type": "state", "users": users, "me": {"photo": self.profile_of(me)["photo"]}}

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

    async def join(self, user: str, ws: WebSocket):
        await ws.accept()
        self.known.add(user)
        self.profile_of(user)
        self.connections.setdefault(user, set()).add(ws)
        # messages sent while this user was offline are delivered now
        delivered = [m for m in self.messages if m["to"] == user and m["status"] == "sent"]
        for m in delivered:
            m["status"] = "delivered"
        mine = [m for m in self.messages if user in (m["from"], m["to"])]
        await ws.send_text(json.dumps({"type": "history", "messages": mine}))
        await self.send_receipts(delivered, "delivered")
        await self.push_state()

    async def leave(self, user: str, ws: WebSocket):
        conns = self.connections.get(user, set())
        conns.discard(ws)
        if not conns:
            self.connections.pop(user, None)
            self.last_seen[user] = self.now()
        await self.push_state()

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
                self.follows.add((me, to))
                await self.send(to, {"type": "notice", "text": f"{me} started following you"})
            elif action == "unfollow":
                self.follows.discard((me, to))
                if rel == "friend":
                    # unfollowing a friend also ends the friendship (no more chat/calls)
                    self.friends.discard(frozenset((me, to)))
            await self.send(me, self.profile_payload(me, to))
            await self.push_state()
            return
        if action == "request" and rel == "none":
            self.requests.add((me, to))
        elif action == "accept" and rel == "received":
            self.requests.discard((to, me))
            self.friends.add(frozenset((me, to)))
            # friends follow each other automatically
            self.follows.add((me, to))
            self.follows.add((to, me))
            await self.send(to, {"type": "notice", "text": f"{me} accepted your friend request"})
        elif action == "decline" and rel == "received":
            self.requests.discard((to, me))
        elif action == "cancel" and rel == "sent":
            self.requests.discard((me, to))
        elif action == "signal" and rel == "friend":
            # WebRTC call signaling (offer/answer/ice/end/reject), relayed as-is
            payload = data.get("data")
            if not isinstance(payload, dict):
                return
            if to in self.connections:
                await self.send(to, {"type": "signal", "from": me, "data": payload})
            elif payload.get("kind") == "offer":
                await self.send(me, {"type": "signal", "from": to, "data": {"kind": "unavailable"}})
            return
        elif action == "message" and rel == "friend":
            text = str(data.get("text", "")).strip()[:2000]
            if not text:
                return
            msg = {"type": "message", "id": self.next_id, "from": me, "to": to, "text": text,
                   "ts": self.now(), "status": "delivered" if to in self.connections else "sent"}
            self.next_id += 1
            self.messages.append(msg)
            await self.send(me, msg)
            await self.send(to, msg)
            return
        elif action == "seen" and rel == "friend":
            # `me` has read everything `to` sent them
            seen = [m for m in self.messages if m["from"] == to and m["to"] == me and m["status"] != "seen"]
            for m in seen:
                m["status"] = "seen"
            await self.send_receipts(seen, "seen")
            return
        else:
            return
        await self.push_state()


manager = ChatManager()


@app.get("/")
async def index():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.websocket("/ws/{user}")
async def chat(ws: WebSocket, user: str):
    user = user.strip()[:30]
    if not user:
        await ws.close()
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
