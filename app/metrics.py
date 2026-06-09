from prometheus_client import Counter, Gauge, Enum, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
from typing import Optional, Set, Dict
import threading

_counters_lock = threading.Lock()

_seen_actors: Set[str] = set()

_events_ingested_total = Counter(
    "audit_events_ingested_total",
    "Total number of audit events ingested, labeled by action, status, service_name",
    ["action", "status", "service_name"],
)

_sensitive_hits_total = Counter(
    "audit_sensitive_hits_total",
    "Total number of audit events marked as sensitive, labeled by severity and matched_rule_id",
    ["severity", "matched_rule_id"],
)

_actor_count = Gauge(
    "audit_distinct_actor_count",
    "Number of distinct actors observed so far",
)

_request_latency_seconds = None
_http_requests_total = None


def _init_http_metrics():
    global _request_latency_seconds, _http_requests_total
    from prometheus_client import Histogram, Counter as PCounter

    _request_latency_seconds = Histogram(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "endpoint", "status_code"],
    )
    _http_requests_total = PCounter(
        "http_requests_total",
        "Total number of HTTP requests",
        ["method", "endpoint", "status_code"],
    )


_init_http_metrics()


def record_event_ingested(
    action: str,
    status: str,
    service_name: Optional[str] = None,
    is_sensitive: bool = False,
    severity: str = "low",
    matched_rule_id: Optional[int] = None,
    actor_id: Optional[str] = None,
):
    global _actor_count

    svc = service_name or "unknown"
    _events_ingested_total.labels(
        action=action, status=status, service_name=svc
    ).inc()

    if is_sensitive:
        rule_id_str = str(matched_rule_id) if matched_rule_id is not None else "none"
        _sensitive_hits_total.labels(
            severity=severity, matched_rule_id=rule_id_str
        ).inc()

    if actor_id:
        with _counters_lock:
            if actor_id not in _seen_actors:
                _seen_actors.add(actor_id)
                _actor_count.set(len(_seen_actors))


def bootstrap_actor_count_from_db(db) -> int:
    from sqlalchemy import func
    from app.models import AuditEvent

    try:
        distinct_actors = (
            db.query(AuditEvent.actor_id)
            .filter(AuditEvent.actor_id.isnot(None))
            .distinct()
            .all()
        )
        actor_ids = {row[0] for row in distinct_actors}

        global _seen_actors
        with _counters_lock:
            _seen_actors = actor_ids
            _actor_count.set(len(actor_ids))

        return len(actor_ids)
    except Exception:
        return 0


def reset_metrics_for_tests():
    global _seen_actors
    _events_ingested_total._metrics.clear()
    _sensitive_hits_total._metrics.clear()
    with _counters_lock:
        _seen_actors = set()
    _actor_count.set(0)


def get_metrics_registry() -> CollectorRegistry:
    from prometheus_client import REGISTRY
    return REGISTRY


def get_metrics_content_type() -> str:
    return CONTENT_TYPE_LATEST


def generate_metrics() -> bytes:
    return generate_latest()
