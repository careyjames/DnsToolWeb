import time
import logging
import threading
from typing import Dict, Any, Optional
from collections import defaultdict
from datetime import datetime


class ProviderHealth:
    __slots__ = ('name', 'total_calls', 'successes', 'failures', 'timeouts',
                 'total_latency_ms', 'last_success', 'last_failure',
                 'last_error', 'consecutive_failures', '_lock')

    def __init__(self, name: str):
        self.name = name
        self.total_calls = 0
        self.successes = 0
        self.failures = 0
        self.timeouts = 0
        self.total_latency_ms = 0.0
        self.last_success: Optional[float] = None
        self.last_failure: Optional[float] = None
        self.last_error: Optional[str] = None
        self.consecutive_failures = 0
        self._lock = threading.Lock()

    def record_success(self, latency_ms: float):
        with self._lock:
            self.total_calls += 1
            self.successes += 1
            self.total_latency_ms += latency_ms
            self.last_success = time.time()
            self.consecutive_failures = 0

    def record_failure(self, error: str, is_timeout: bool = False):
        with self._lock:
            self.total_calls += 1
            self.failures += 1
            if is_timeout:
                self.timeouts += 1
            self.last_failure = time.time()
            self.last_error = error
            self.consecutive_failures += 1

    @property
    def success_rate(self) -> float:
        with self._lock:
            if self.total_calls == 0:
                return 1.0
            return self.successes / self.total_calls

    @property
    def avg_latency_ms(self) -> float:
        with self._lock:
            if self.successes == 0:
                return 0.0
            return self.total_latency_ms / self.successes

    @property
    def is_healthy(self) -> bool:
        with self._lock:
            if self.total_calls < 3:
                return True
            sr = self.successes / self.total_calls if self.total_calls > 0 else 1.0
            return self.consecutive_failures < 5 and sr > 0.3

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            sr = self.successes / self.total_calls if self.total_calls > 0 else 1.0
            avg_lat = self.total_latency_ms / self.successes if self.successes > 0 else 0.0
            healthy = True if self.total_calls < 3 else (self.consecutive_failures < 5 and sr > 0.3)
            return {
                'name': self.name,
                'total_calls': self.total_calls,
                'successes': self.successes,
                'failures': self.failures,
                'timeouts': self.timeouts,
                'success_rate': round(sr, 3) if self.total_calls > 0 else None,
                'avg_latency_ms': round(avg_lat, 1) if self.successes > 0 else None,
                'consecutive_failures': self.consecutive_failures,
                'is_healthy': healthy,
                'last_success': datetime.fromtimestamp(self.last_success).isoformat() if self.last_success else None,
                'last_failure': datetime.fromtimestamp(self.last_failure).isoformat() if self.last_failure else None,
                'last_error': self.last_error,
            }


BACKOFF_BASE_MS = 500
BACKOFF_MAX_MS = 30000
BACKOFF_MULTIPLIER = 2


def calculate_backoff_ms(consecutive_failures: int) -> int:
    if consecutive_failures <= 0:
        return 0
    delay = BACKOFF_BASE_MS * (BACKOFF_MULTIPLIER ** min(consecutive_failures - 1, 6))
    return min(int(delay), BACKOFF_MAX_MS)


DEFAULT_TIMEOUTS = {
    'rdap': 10,
    'rdap_whodap': 8,
    'whois': 8,
    'ct_logs': 12,
    'doh': 5,
    'dns_resolver': 2,
    'smtp': 1.5,
    'smtp_connect': 1.5,
    'iana_bootstrap': 5,
    'mta_sts_policy': 8,
    'bimi_logo': 5,
    'ssrf_validation': 3,
}


class NetworkTelemetry:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._providers: Dict[str, ProviderHealth] = {}
        self._providers_lock = threading.Lock()
        self._timeouts = dict(DEFAULT_TIMEOUTS)
        self._event_log = []
        self._event_log_lock = threading.Lock()
        self._max_events = 500
        self._initialized = True

    def get_provider(self, name: str) -> ProviderHealth:
        with self._providers_lock:
            if name not in self._providers:
                self._providers[name] = ProviderHealth(name)
            return self._providers[name]

    def record_call(self, provider: str, success: bool, latency_ms: float,
                    error: Optional[str] = None, is_timeout: bool = False,
                    operation: Optional[str] = None):
        p = self.get_provider(provider)
        if success:
            p.record_success(latency_ms)
        else:
            p.record_failure(error or 'unknown', is_timeout=is_timeout)

        failure_level = 'WARNING' if is_timeout else 'ERROR'
        level = 'DEBUG' if success else failure_level
        event = {
            'timestamp': time.time(),
            'provider': provider,
            'operation': operation,
            'success': success,
            'latency_ms': round(latency_ms, 1),
            'error': error,
            'is_timeout': is_timeout,
            'level': level,
        }
        with self._event_log_lock:
            self._event_log.append(event)
            if len(self._event_log) > self._max_events:
                self._event_log = self._event_log[-self._max_events:]

        if not success:
            log_msg = f"[TELEMETRY] {provider}"
            if operation:
                log_msg += f"/{operation}"
            log_msg += f" FAILED ({latency_ms:.0f}ms)"
            if error:
                log_msg += f": {error}"
            if is_timeout:
                log_msg += " [TIMEOUT]"
            logging.warning(log_msg)

    def should_backoff(self, provider: str) -> bool:
        p = self.get_provider(provider)
        if p.consecutive_failures < 3:
            return False
        backoff_ms = calculate_backoff_ms(p.consecutive_failures)
        if p.last_failure and (time.time() - p.last_failure) * 1000 < backoff_ms:
            return True
        return False

    def get_backoff_seconds(self, provider: str) -> float:
        p = self.get_provider(provider)
        backoff_ms = calculate_backoff_ms(p.consecutive_failures)
        return backoff_ms / 1000.0

    def get_timeout(self, operation: str) -> float:
        return self._timeouts.get(operation, 10)

    def set_timeout(self, operation: str, seconds: float):
        self._timeouts[operation] = seconds

    def get_all_health(self) -> Dict[str, Any]:
        with self._providers_lock:
            providers = {name: p.to_dict() for name, p in self._providers.items()}
        unhealthy = [name for name, p in providers.items() if not p.get('is_healthy', True)]
        total_calls = sum(p.get('total_calls', 0) for p in providers.values())
        total_failures = sum(p.get('failures', 0) for p in providers.values())
        return {
            'providers': providers,
            'summary': {
                'total_providers': len(providers),
                'unhealthy_providers': unhealthy,
                'total_calls': total_calls,
                'total_failures': total_failures,
                'overall_success_rate': round(1 - total_failures / total_calls, 3) if total_calls > 0 else None,
            },
            'timeouts': dict(self._timeouts),
        }

    def get_recent_events(self, count: int = 50, provider: Optional[str] = None,
                          errors_only: bool = False) -> list:
        with self._event_log_lock:
            events = list(self._event_log)
        if provider:
            events = [e for e in events if e['provider'] == provider]
        if errors_only:
            events = [e for e in events if not e['success']]
        return events[-count:]

    def reset(self):
        with self._providers_lock:
            self._providers.clear()
        with self._event_log_lock:
            self._event_log.clear()

    @classmethod
    def reset_instance(cls):
        with cls._lock:
            cls._instance = None


_telemetry = NetworkTelemetry()


def get_telemetry() -> NetworkTelemetry:
    return _telemetry


class TelemetryTimer:
    def __init__(self, provider: str, operation: Optional[str] = None,
                 telemetry: Optional[NetworkTelemetry] = None):
        self.provider = provider
        self.operation = operation
        self.telemetry = telemetry or _telemetry
        self._start = None

    def __enter__(self):
        self._start = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed_ms = (time.time() - self._start) * 1000
        if exc_type is None:
            self.telemetry.record_call(
                self.provider, success=True, latency_ms=elapsed_ms,
                operation=self.operation)
        else:
            is_timeout = 'timeout' in str(exc_type.__name__).lower() or 'timeout' in str(exc_val).lower()
            self.telemetry.record_call(
                self.provider, success=False, latency_ms=elapsed_ms,
                error=f"{exc_type.__name__}: {str(exc_val)[:200]}",
                is_timeout=is_timeout, operation=self.operation)
        return False
