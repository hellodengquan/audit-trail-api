from limits.storage import MemoryStorage
from limits.strategies import FixedWindowRateLimiter
from limits import parse
from fastapi import Request, HTTPException
from typing import Optional, Tuple
import json

from app.config import settings

_storage = MemoryStorage()
_window = FixedWindowRateLimiter(storage=_storage)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    if request.client:
        return request.client.host
    return "unknown"


async def _extract_info(request: Request) -> Tuple[Optional[str], int]:
    actor_id: Optional[str] = None
    cost: int = 1

    if request.method != "POST":
        return actor_id, cost

    if "application/json" not in request.headers.get("content-type", ""):
        return actor_id, cost

    if not hasattr(request, "_rate_body_cache"):
        try:
            raw = await request.body()
            request._rate_body_cache = raw or b""
        except Exception:
            request._rate_body_cache = b""

    raw = getattr(request, "_rate_body_cache", b"")
    if not raw:
        return actor_id, cost

    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return actor_id, cost

    if isinstance(data, list):
        cost = max(1, min(len(data), 1000))
        if data and isinstance(data[0], dict):
            actor_id = data[0].get("actor_id")
    elif isinstance(data, dict):
        actor_id = data.get("actor_id")

    return actor_id, cost


def _check_one(key: str, limit_str: str, cost: int) -> Tuple[bool, int]:
    lim = parse(limit_str)
    ok = True
    for _ in range(cost):
        res = _window.hit(lim, key)
        if res is False:
            ok = False
            break
    remaining = 0
    try:
        stats = _window.get_window_stats(lim, key)
        if stats and hasattr(stats, "remaining_count"):
            remaining = stats.remaining_count
    except Exception:
        pass
    return ok, remaining


async def enforce_events_rate_limit(request: Request):
    if not settings.RATE_LIMIT_ENABLED:
        return

    ip = _client_ip(request)
    actor_id, cost = await _extract_info(request)

    per_ip = settings.RATE_LIMIT_EVENTS_PER_MINUTE_IP
    per_actor = settings.RATE_LIMIT_EVENTS_PER_MINUTE_ACTOR
    ip_limit_str = f"{per_ip}/minute"
    actor_limit_str = f"{per_actor}/minute"

    ip_key = f"audit:ip:{ip}"
    ok_ip, _ = _check_one(ip_key, ip_limit_str, cost)
    if not ok_ip:
        raise HTTPException(
            status_code=429,
            detail={
                "message": "Too many requests for this IP",
                "type": "rate_limit",
                "scope": "ip",
                "limit": per_ip,
                "window_seconds": 60,
            },
        )

    if actor_id:
        actor_key = f"audit:actor:{actor_id}"
        ok_actor, _ = _check_one(actor_key, actor_limit_str, cost)
        if not ok_actor:
            raise HTTPException(
                status_code=429,
                detail={
                    "message": f"Too many requests for actor_id={actor_id}",
                    "type": "rate_limit",
                    "scope": "actor_id",
                    "limit": per_actor,
                    "window_seconds": 60,
                },
            )


def reset_rate_limiter_storage():
    global _storage
    _storage.reset()
