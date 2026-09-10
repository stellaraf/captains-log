"""Forecast from measured newly-written database bytes, never a fixed EPS ratio."""
from __future__ import annotations
from dataclasses import asdict, dataclass
import math

@dataclass(frozen=True)
class Measurement:
    hours: float
    written_bytes: int
    events: int


def forecast(capacity_bytes: int, used_bytes: int, samples: list[Measurement], reserve: float = .15) -> dict:
    if capacity_bytes <= 0 or used_bytes < 0 or used_bytes > capacity_bytes:
        raise ValueError("Invalid filesystem capacity/usage")
    if not 0 < reserve < .5:
        raise ValueError("Reserve must be between 0 and 0.5")
    if any(not math.isfinite(s.hours) or s.hours <= 0 or s.written_bytes < 0 or s.events < 0 for s in samples):
        raise ValueError("Measurements require positive duration and nonnegative counts")
    hours = sum(s.hours for s in samples)
    written = sum(s.written_bytes for s in samples)
    events = sum(s.events for s in samples)
    per_day = written * 24 / hours if hours else None
    usable = capacity_bytes * (1 - reserve)
    ratio = used_bytes / capacity_bytes
    level = "emergency" if ratio >= .95 else "critical" if ratio >= .90 else "warning" if ratio >= .80 else "information" if ratio >= .70 else "normal"
    # Round recommendations up to decimal 100 GB; never imply a TB means fixed days.
    requirement = lambda days: math.ceil((per_day * days / (1-reserve)) / 100_000_000_000) * 100_000_000_000
    return {"capacity_bytes": capacity_bytes, "used_bytes": used_bytes,
            "free_bytes": capacity_bytes-used_bytes, "reserve_fraction": reserve,
            "reserve_bytes": math.ceil(capacity_bytes * reserve), "level": level,
            "sample_hours": hours, "confidence": "insufficient" if hours < 24 else "preliminary" if hours < 168 else "measured",
            "measured_growth_bytes_per_day": per_day, "measured_bytes_per_event": written/events if events else None,
            "average_eps": events/(hours*3600) if hours else None,
            "estimated_retention_days": usable/per_day if per_day else None,
            "days_until_reserve": max(0, usable-used_bytes)/per_day if per_day else None,
            "days_until_full": (capacity_bytes-used_bytes)/per_day if per_day else None,
            "required_capacity_bytes": {str(d): requirement(d) for d in (30, 60, 90, 180, 365)} if per_day else {}}
