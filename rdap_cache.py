import os
import time
import logging
from typing import Dict, Optional
from threading import Lock

_RDAP_CACHE_TTL = 21600  # 6 hours - registrar/registry data changes infrequently


class RDAPCache:
    """Hybrid RDAP cache - uses Redis if available, falls back to in-memory.
    
    Thread-safe: all in-memory cache operations are protected by a lock.
    """
    
    def __init__(self):
        self._memory_cache: Dict[str, tuple] = {}  # In-memory fallback
        self._lock = Lock()
        self._redis = None
        self._use_redis = False
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis connection if REDIS_URL is set."""
        redis_url = os.environ.get('REDIS_URL')
        if redis_url:
            try:
                import redis
                self._redis = redis.from_url(redis_url, decode_responses=True)
                self._redis.ping()
                self._use_redis = True
                logging.info("RDAP cache using Redis backend")
            except Exception as e:
                logging.warning(f"Redis connection failed for RDAP cache, using memory: {e}")
                self._use_redis = False
    
    def get(self, domain: str) -> Optional[Dict]:
        """Get cached RDAP data for domain."""
        cache_key = f"rdap:{domain.lower()}"
        
        if self._use_redis:
            try:
                import json
                cached = self._redis.get(cache_key)
                if cached:
                    return json.loads(cached)
                return None
            except Exception as e:
                logging.debug(f"Redis get failed: {e}")
                # Fall through to memory cache
        
        with self._lock:
            if domain.lower() in self._memory_cache:
                timestamp, data = self._memory_cache[domain.lower()]
                if time.time() - timestamp < _RDAP_CACHE_TTL:
                    return data
                else:
                    del self._memory_cache[domain.lower()]
        return None
    
    def set(self, domain: str, data: Dict):
        """Cache RDAP data for domain."""
        cache_key = f"rdap:{domain.lower()}"
        
        if self._use_redis:
            try:
                import json
                self._redis.setex(cache_key, _RDAP_CACHE_TTL, json.dumps(data))
            except Exception as e:
                logging.debug(f"Redis set failed: {e}")
                # Fall through to memory cache
        
        with self._lock:
            self._memory_cache[domain.lower()] = (time.time(), data)
    
    def clear(self):
        """Clear all cached data (primarily for testing)."""
        with self._lock:
            self._memory_cache.clear()
        if self._use_redis:
            try:
                # Clear only RDAP keys
                for key in self._redis.scan_iter("rdap:*"):
                    self._redis.delete(key)
            except Exception:
                pass
    
    @property
    def backend(self) -> str:
        """Return the current backend type."""
        return 'redis' if self._use_redis else 'memory'


# Global RDAP cache instance
_rdap_cache = RDAPCache()
