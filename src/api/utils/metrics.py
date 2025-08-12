"""
Simple metrics collection for authentication operations.
Lightweight alternative to Prometheus for MVP.
"""

from typing import Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading

from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class SimpleMetrics:
    """Simple in-memory metrics collector for authentication operations."""
    
    def __init__(self, retention_hours: int = 24):
        self._lock = threading.Lock()
        self._retention_hours = retention_hours
        
        # Time-series data (timestamp, value) pairs
        self._auth_success = deque()
        self._auth_failures = deque()
        self._challenge_created = deque()
        self._protocol_usage = defaultdict(lambda: deque())
        
        # Current counters
        self._counters = {
            'total_auth_attempts': 0,
            'total_auth_success': 0,
            'total_auth_failures': 0,
            'total_challenges': 0,
            'active_sessions': 0
        }
        
        # Protocol-specific counters
        self._protocol_counters = defaultdict(lambda: {
            'auth_attempts': 0,
            'auth_success': 0,
            'auth_failures': 0,
            'challenges': 0
        })
    
    def _cleanup_old_data(self):
        """Remove data older than retention period."""
        cutoff_time = datetime.utcnow() - timedelta(hours=self._retention_hours)
        
        def cleanup_deque(data_deque):
            while data_deque and data_deque[0][0] < cutoff_time:
                data_deque.popleft()
        
        cleanup_deque(self._auth_success)
        cleanup_deque(self._auth_failures)
        cleanup_deque(self._challenge_created)
        
        for protocol_deque in self._protocol_usage.values():
            cleanup_deque(protocol_deque)
    
    def record_challenge_created(self, protocol: str):
        """Record a challenge creation event."""
        with self._lock:
            now = datetime.utcnow()
            self._challenge_created.append((now, 1))
            self._counters['total_challenges'] += 1
            self._protocol_counters[protocol]['challenges'] += 1
            self._cleanup_old_data()
    
    def record_auth_attempt(self, protocol: str, success: bool):
        """Record an authentication attempt."""
        with self._lock:
            now = datetime.utcnow()
            
            self._counters['total_auth_attempts'] += 1
            self._protocol_counters[protocol]['auth_attempts'] += 1
            
            if success:
                self._auth_success.append((now, 1))
                self._counters['total_auth_success'] += 1
                self._protocol_counters[protocol]['auth_success'] += 1
            else:
                self._auth_failures.append((now, 1))
                self._counters['total_auth_failures'] += 1
                self._protocol_counters[protocol]['auth_failures'] += 1
            
            self._protocol_usage[protocol].append((now, 1 if success else 0))
            self._cleanup_old_data()
    
    def record_session_change(self, delta: int):
        """Record session count change (+1 for login, -1 for logout)."""
        with self._lock:
            self._counters['active_sessions'] = max(0, self._counters['active_sessions'] + delta)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get current metrics summary."""
        with self._lock:
            self._cleanup_old_data()
            
            # Calculate rates for the last hour
            one_hour_ago = datetime.utcnow() - timedelta(hours=1)
            
            recent_success = sum(1 for ts, _ in self._auth_success if ts > one_hour_ago)
            recent_failures = sum(1 for ts, _ in self._auth_failures if ts > one_hour_ago)
            recent_challenges = sum(1 for ts, _ in self._challenge_created if ts > one_hour_ago)
            
            # Calculate success rate
            total_recent = recent_success + recent_failures
            success_rate = (recent_success / total_recent * 100) if total_recent > 0 else 0
            
            # Protocol-specific metrics
            protocol_metrics = {}
            for protocol, counters in self._protocol_counters.items():
                protocol_total = counters['auth_success'] + counters['auth_failures']
                protocol_success_rate = (counters['auth_success'] / protocol_total * 100) if protocol_total > 0 else 0
                
                protocol_metrics[protocol] = {
                    'total_attempts': counters['auth_attempts'],
                    'success_count': counters['auth_success'],
                    'failure_count': counters['auth_failures'],
                    'success_rate_percent': round(protocol_success_rate, 2),
                    'challenges_created': counters['challenges']
                }
            
            return {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'overall': {
                    'total_auth_attempts': self._counters['total_auth_attempts'],
                    'total_auth_success': self._counters['total_auth_success'],
                    'total_auth_failures': self._counters['total_auth_failures'],
                    'total_challenges': self._counters['total_challenges'],
                    'active_sessions': self._counters['active_sessions'],
                    'success_rate_percent': round(success_rate, 2)
                },
                'last_hour': {
                    'auth_success': recent_success,
                    'auth_failures': recent_failures,
                    'challenges_created': recent_challenges,
                    'success_rate_percent': round(success_rate, 2)
                },
                'by_protocol': protocol_metrics,
                'retention_hours': self._retention_hours
            }
    
    def get_health_metrics(self) -> Dict[str, str]:
        """Get basic health metrics for health check."""
        with self._lock:
            # Check if we have recent activity (last 5 minutes)
            five_min_ago = datetime.utcnow() - timedelta(minutes=5)
            recent_activity = any(
                ts > five_min_ago for ts, _ in list(self._auth_success)[-10:] + list(self._auth_failures)[-10:]
            )
            
            # Calculate error rate in last hour
            one_hour_ago = datetime.utcnow() - timedelta(hours=1)
            recent_success = sum(1 for ts, _ in self._auth_success if ts > one_hour_ago)
            recent_failures = sum(1 for ts, _ in self._auth_failures if ts > one_hour_ago)
            
            total_recent = recent_success + recent_failures
            error_rate = (recent_failures / total_recent * 100) if total_recent > 0 else 0
            
            # Determine health status
            if error_rate > 50:
                status = "unhealthy"
            elif error_rate > 20:
                status = "degraded"
            else:
                status = "healthy"
            
            return {
                'status': status,
                'recent_activity': 'yes' if recent_activity else 'no',
                'error_rate_percent': f"{error_rate:.1f}",
                'active_sessions': str(self._counters['active_sessions'])
            }


# Global metrics instance
metrics = SimpleMetrics()


def get_metrics() -> SimpleMetrics:
    """Get the global metrics instance."""
    return metrics
