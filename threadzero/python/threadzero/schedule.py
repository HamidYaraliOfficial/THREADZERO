"""Time-Bounded Access Engine: opening hours, maintenance and emergency windows.
Users enter windows; the engine reports whether each is open *now*, how long until it changes,
and when the next opening / closing happens (time-zone and overnight aware)."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
WEEK = 7 * 86400


def expand_days(days: Any) -> list[int]:
    if days in (None, "", "daily"):
        return list(range(7))
    if days == "weekdays":
        return list(range(5))
    if days == "weekends":
        return [5, 6]
    if isinstance(days, str):
        days = [days]
    out = []
    for d in days:
        if isinstance(d, int):
            out.append(d % 7)
        else:
            k = str(d).strip().lower()[:3]
            if k in DAYS:
                out.append(DAYS.index(k))
    return sorted(set(out))


def _hm(v: Any) -> int:
    if isinstance(v, int):
        return v
    h, m = str(v).split(":")
    return int(h) * 60 + int(m)


def intervals(w: dict) -> list[tuple[int, int]]:
    """Merged [start,end) intervals in seconds-of-week (Monday 00:00 = 0); may extend past WEEK when wrapping."""
    a, b = _hm(w.get("from", "00:00")) * 60, _hm(w.get("to", "24:00")) * 60
    raw: list[tuple[int, int]] = []
    for d in expand_days(w.get("days")):
        base = d * 86400
        if b > a:
            raw.append((base + a, base + b))
        elif b == a:
            raw.append((base, base + 86400))
        else:  # overnight
            raw.append((base + a, base + 86400 + b))
    raw.sort()
    merged: list[list[int]] = []
    for s, e in raw:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    if len(merged) > 1 and merged[-1][1] >= WEEK and merged[0][0] <= merged[-1][1] - WEEK:
        merged[-1][1] = max(merged[-1][1], merged[0][1] + WEEK)
        merged.pop(0)
    return [(s, e) for s, e in merged]


def human(seconds: float) -> str:
    s = int(max(0, round(seconds)))
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    parts = [f"{d}d" if d else "", f"{h}h" if h or d else "", f"{m}m" if m or h or d else "", f"{s}s"]
    return " ".join(p for p in parts if p)


def evaluate_window(w: dict, now: datetime | None = None, default_tz: str = "UTC") -> dict:
    tz = ZoneInfo(w.get("tz") or default_tz)
    now = (now or datetime.now(tz)).astimezone(tz)
    t = now.weekday() * 86400 + now.hour * 3600 + now.minute * 60 + now.second
    ivs = intervals(w)
    state: dict[str, Any] = {"name": w.get("name", ""), "label": w.get("label", ""), "kind": w.get("kind", "open"), "tz": str(tz),
                             "now_local": now.isoformat(timespec="seconds"), "weekday": DAYS[now.weekday()], "intervals": [
                                 {"day": DAYS[(s // 86400) % 7], "from": f"{(s % 86400) // 3600:02d}:{(s % 3600) // 60:02d}", "to": f"{(e % 86400) // 3600:02d}:{(e % 3600) // 60:02d}"} for s, e in ivs]}
    if not ivs:
        return {**state, "is_open": False, "seconds_until_change": None, "next_change": None, "text": "never open"}
    cur = next(((s, e) for s, e in ivs if s <= t < e or s <= t + WEEK < e), None)
    if cur:
        tt = t if cur[0] <= t < cur[1] else t + WEEK
        left = cur[1] - tt
        nxt = now + timedelta(seconds=left)
        return {**state, "is_open": True, "seconds_until_change": left, "next_change": nxt.isoformat(timespec="seconds"), "next_close": nxt.isoformat(timespec="seconds"),
                "seconds_until_close": left, "text": f"open now — closes in {human(left)}"}
    starts = sorted(((s - t) % WEEK or WEEK, s, e) for s, e in ivs)
    wait, s, e = starts[0]
    opens = now + timedelta(seconds=wait)
    closes = opens + timedelta(seconds=(e - s))
    return {**state, "is_open": False, "seconds_until_change": wait, "next_change": opens.isoformat(timespec="seconds"), "next_open": opens.isoformat(timespec="seconds"),
            "next_close": closes.isoformat(timespec="seconds"), "seconds_until_open": wait, "open_duration_seconds": e - s,
            "text": f"closed — opens in {human(wait)} for {human(e - s)}"}


def evaluate(windows: list[dict], now: str | datetime | None = None, default_tz: str = "UTC") -> list[dict]:
    dt = None
    if isinstance(now, str) and now:
        dt = datetime.fromisoformat(now)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo(default_tz))
    elif isinstance(now, datetime):
        dt = now
    return [evaluate_window(w, dt, default_tz) for w in windows]


def windows_from_ast(A: dict) -> list[dict]:
    out = []
    for w in A["ast"]["windows"]:
        p = w["props"]
        out.append({"name": w["name"], "days": p.get("days", "daily"), "from": p.get("from", "00:00"), "to": p.get("to", "24:00"),
                    "kind": p.get("kind", "open"), "label": p.get("label", ""), "tz": p.get("tz", A["project"]["timezone"])})
    return out


def windows_to_dsl(windows: list[dict]) -> str:
    lines = []
    for w in windows:
        days = expand_days(w.get("days"))
        d = "daily" if days == list(range(7)) else "weekdays" if days == list(range(5)) else "weekends" if days == [5, 6] else "[" + ", ".join(DAYS[i] for i in days) + "]"
        props = [f"days: {d};", f"from: {w.get('from', '00:00')};", f"to: {w.get('to', '24:00')};", f"kind: {w.get('kind', 'open')};"]
        if w.get("label"):
            props.append('label: "' + str(w["label"]).replace('"', "'") + '";')
        if w.get("tz"):
            props.append('tz: "' + w["tz"] + '";')
        lines.append(f"window {w['name']} {{ " + " ".join(props) + " }")
    return "\n".join(lines)
