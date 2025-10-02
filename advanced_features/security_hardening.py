"""
Security Hardening Module

This module provides security hardening features including intrusion detection,
brute force protection, secure logging, and other defensive mechanisms.
"""

import time
import hashlib
import logging
import threading
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
import json
import os


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEventType(Enum):
    """Types of security events."""
    AUTHENTICATION_FAILURE = "auth_failure"
    BRUTE_FORCE_ATTEMPT = "brute_force"
    INVALID_INPUT = "invalid_input"
    ENCRYPTION_FAILURE = "encryption_failure"
    KEY_COMPROMISE_SUSPECTED = "key_compromise"
    UNUSUAL_ACTIVITY = "unusual_activity"
    SYSTEM_INTRUSION = "system_intrusion"


@dataclass
class SecurityEvent:
    """Security event data structure."""
    event_type: SecurityEventType
    threat_level: ThreatLevel
    timestamp: float
    source_ip: Optional[str]
    user_id: Optional[str]
    description: str
    metadata: Dict[str, Any]


class BruteForceProtection:
    """Protection against brute force attacks."""
    
    def __init__(self, max_attempts: int = 5, lockout_duration: int = 300):
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration  # seconds
        self.attempts = defaultdict(list)  # IP -> list of attempt timestamps
        self.locked_ips = {}  # IP -> lockout timestamp
        self.lock = threading.Lock()
    
    def is_locked(self, source_ip: str) -> bool:
        """Check if an IP is currently locked out."""
        with self.lock:
            if source_ip in self.locked_ips:
                lockout_time = self.locked_ips[source_ip]
                if time.time() - lockout_time < self.lockout_duration:
                    return True
                else:
                    # Lockout expired, remove it
                    del self.locked_ips[source_ip]
                    self.attempts[source_ip].clear()
            return False
    
    def record_attempt(self, source_ip: str, success: bool) -> bool:
        """
        Record an authentication attempt.
        
        Args:
            source_ip: Source IP address
            success: Whether the attempt was successful
            
        Returns:
            True if the IP should be locked out
        """
        with self.lock:
            current_time = time.time()
            
            if success:
                # Clear attempts on successful authentication
                if source_ip in self.attempts:
                    self.attempts[source_ip].clear()
                return False
            
            # Record failed attempt
            self.attempts[source_ip].append(current_time)
            
            # Remove old attempts (older than lockout duration)
            cutoff_time = current_time - self.lockout_duration
            self.attempts[source_ip] = [
                t for t in self.attempts[source_ip] if t > cutoff_time
            ]
            
            # Check if we should lock out
            if len(self.attempts[source_ip]) >= self.max_attempts:
                self.locked_ips[source_ip] = current_time
                return True
            
            return False
    
    def get_remaining_attempts(self, source_ip: str) -> int:
        """Get remaining attempts before lockout."""
        with self.lock:
            if self.is_locked(source_ip):
                return 0
            
            current_attempts = len(self.attempts.get(source_ip, []))
            return max(0, self.max_attempts - current_attempts)
    
    def get_lockout_remaining(self, source_ip: str) -> int:
        """Get remaining lockout time in seconds."""
        with self.lock:
            if source_ip in self.locked_ips:
                elapsed = time.time() - self.locked_ips[source_ip]
                remaining = max(0, self.lockout_duration - elapsed)
                return int(remaining)
            return 0


class AnomalyDetector:
    """Detect anomalous behavior patterns."""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.operation_history = deque(maxlen=window_size)
        self.baseline_metrics = {}
        self.lock = threading.Lock()
    
    def record_operation(self, operation_type: str, duration: float, 
                        success: bool, metadata: Dict[str, Any] = None):
        """Record a cryptographic operation."""
        with self.lock:
            operation = {
                'type': operation_type,
                'duration': duration,
                'success': success,
                'timestamp': time.time(),
                'metadata': metadata or {}
            }
            self.operation_history.append(operation)
            self._update_baseline()
    
    def _update_baseline(self):
        """Update baseline metrics from operation history."""
        if len(self.operation_history) < 10:
            return
        
        # Calculate baseline metrics
        operations_by_type = defaultdict(list)
        for op in self.operation_history:
            operations_by_type[op['type']].append(op)
        
        for op_type, ops in operations_by_type.items():
            durations = [op['duration'] for op in ops if op['success']]
            if durations:
                self.baseline_metrics[op_type] = {
                    'avg_duration': sum(durations) / len(durations),
                    'max_duration': max(durations),
                    'success_rate': sum(1 for op in ops if op['success']) / len(ops)
                }
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect anomalous patterns in recent operations."""
        anomalies = []
        
        with self.lock:
            if len(self.operation_history) < 20:
                return anomalies
            
            recent_ops = list(self.operation_history)[-10:]  # Last 10 operations
            
            # Check for unusual failure rates
            failure_rate = sum(1 for op in recent_ops if not op['success']) / len(recent_ops)
            if failure_rate > 0.5:  # More than 50% failures
                anomalies.append({
                    'type': 'high_failure_rate',
                    'severity': ThreatLevel.MEDIUM,
                    'description': f'High failure rate detected: {failure_rate:.2%}',
                    'metadata': {'failure_rate': failure_rate}
                })
            
            # Check for unusual operation durations
            for op in recent_ops[-5:]:  # Check last 5 operations
                if op['type'] in self.baseline_metrics:
                    baseline = self.baseline_metrics[op['type']]
                    if op['duration'] > baseline['max_duration'] * 2:
                        anomalies.append({
                            'type': 'unusual_duration',
                            'severity': ThreatLevel.LOW,
                            'description': f'Operation {op["type"]} took unusually long: {op["duration"]:.2f}s',
                            'metadata': {'operation': op, 'baseline': baseline}
                        })
            
            # Check for rapid successive operations (potential automation)
            timestamps = [op['timestamp'] for op in recent_ops]
            if len(timestamps) >= 5:
                time_diffs = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
                avg_interval = sum(time_diffs) / len(time_diffs)
                if avg_interval < 0.1:  # Less than 100ms between operations
                    anomalies.append({
                        'type': 'rapid_operations',
                        'severity': ThreatLevel.MEDIUM,
                        'description': f'Rapid successive operations detected (avg interval: {avg_interval:.3f}s)',
                        'metadata': {'avg_interval': avg_interval}
                    })
        
        return anomalies


class SecureLogger:
    """Secure logging with integrity protection."""
    
    def __init__(self, log_file: str, integrity_key: bytes):
        self.log_file = log_file
        self.integrity_key = integrity_key
        self.lock = threading.Lock()
        
        # Ensure log directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    def log_security_event(self, event: SecurityEvent):
        """Log a security event with integrity protection."""
        with self.lock:
            log_entry = {
                'timestamp': event.timestamp,
                'event_type': event.event_type.value,
                'threat_level': event.threat_level.value,
                'source_ip': event.source_ip,
                'user_id': event.user_id,
                'description': event.description,
                'metadata': event.metadata
            }
            
            # Serialize log entry
            log_data = json.dumps(log_entry, sort_keys=True)
            
            # Calculate integrity hash
            integrity_hash = hashlib.hmac.new(
                self.integrity_key,
                log_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Write to log file
            with open(self.log_file, 'a') as f:
                f.write(f"{log_data}|{integrity_hash}\n")
    
    def verify_log_integrity(self) -> bool:
        """Verify the integrity of the log file."""
        try:
            with open(self.log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        log_data, stored_hash = line.rsplit('|', 1)
                        calculated_hash = hashlib.hmac.new(
                            self.integrity_key,
                            log_data.encode(),
                            hashlib.sha256
                        ).hexdigest()
                        
                        if calculated_hash != stored_hash:
                            logging.error(f"Log integrity violation at line {line_num}")
                            return False
                    except ValueError:
                        logging.error(f"Malformed log entry at line {line_num}")
                        return False
            
            return True
        except FileNotFoundError:
            return True  # Empty log is valid


class SecurityHardeningManager:
    """Main security hardening manager."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Initialize components
        self.brute_force_protection = BruteForceProtection(
            max_attempts=self.config.get('max_auth_attempts', 5),
            lockout_duration=self.config.get('lockout_duration', 300)
        )
        
        self.anomaly_detector = AnomalyDetector(
            window_size=self.config.get('anomaly_window_size', 100)
        )
        
        # Initialize secure logger
        log_file = self.config.get('security_log_file', '/tmp/security.log')
        integrity_key = self.config.get('log_integrity_key', os.urandom(32))
        self.secure_logger = SecureLogger(log_file, integrity_key)
        
        # Event handlers
        self.event_handlers: Dict[SecurityEventType, List[Callable]] = defaultdict(list)
        
        # Security metrics
        self.metrics = {
            'total_events': 0,
            'events_by_type': defaultdict(int),
            'events_by_threat_level': defaultdict(int),
            'blocked_ips': set(),
            'start_time': time.time()
        }
    
    def register_event_handler(self, event_type: SecurityEventType, 
                             handler: Callable[[SecurityEvent], None]):
        """Register a handler for specific security events."""
        self.event_handlers[event_type].append(handler)
    
    def report_security_event(self, event_type: SecurityEventType, 
                            threat_level: ThreatLevel,
                            description: str,
                            source_ip: Optional[str] = None,
                            user_id: Optional[str] = None,
                            metadata: Dict[str, Any] = None):
        """Report a security event."""
        event = SecurityEvent(
            event_type=event_type,
            threat_level=threat_level,
            timestamp=time.time(),
            source_ip=source_ip,
            user_id=user_id,
            description=description,
            metadata=metadata or {}
        )
        
        # Log the event
        self.secure_logger.log_security_event(event)
        
        # Update metrics
        self.metrics['total_events'] += 1
        self.metrics['events_by_type'][event_type] += 1
        self.metrics['events_by_threat_level'][threat_level] += 1
        
        # Call event handlers
        for handler in self.event_handlers[event_type]:
            try:
                handler(event)
            except Exception as e:
                logging.error(f"Error in security event handler: {e}")
        
        # Take automatic actions based on threat level
        if threat_level == ThreatLevel.CRITICAL:
            self._handle_critical_threat(event)
        elif threat_level == ThreatLevel.HIGH:
            self._handle_high_threat(event)
    
    def _handle_critical_threat(self, event: SecurityEvent):
        """Handle critical security threats."""
        if event.source_ip:
            self.metrics['blocked_ips'].add(event.source_ip)
            logging.critical(f"CRITICAL THREAT: {event.description} from {event.source_ip}")
    
    def _handle_high_threat(self, event: SecurityEvent):
        """Handle high-level security threats."""
        logging.warning(f"HIGH THREAT: {event.description}")
    
    def check_authentication(self, source_ip: str, success: bool, 
                           user_id: Optional[str] = None) -> bool:
        """Check authentication attempt and apply brute force protection."""
        if self.brute_force_protection.is_locked(source_ip):
            remaining = self.brute_force_protection.get_lockout_remaining(source_ip)
            self.report_security_event(
                SecurityEventType.BRUTE_FORCE_ATTEMPT,
                ThreatLevel.HIGH,
                f"Authentication attempt from locked IP {source_ip}",
                source_ip=source_ip,
                user_id=user_id,
                metadata={'lockout_remaining': remaining}
            )
            return False
        
        should_lock = self.brute_force_protection.record_attempt(source_ip, success)
        
        if not success:
            remaining = self.brute_force_protection.get_remaining_attempts(source_ip)
            threat_level = ThreatLevel.MEDIUM if remaining <= 2 else ThreatLevel.LOW
            
            self.report_security_event(
                SecurityEventType.AUTHENTICATION_FAILURE,
                threat_level,
                f"Authentication failure from {source_ip}",
                source_ip=source_ip,
                user_id=user_id,
                metadata={'remaining_attempts': remaining}
            )
            
            if should_lock:
                self.report_security_event(
                    SecurityEventType.BRUTE_FORCE_ATTEMPT,
                    ThreatLevel.HIGH,
                    f"IP {source_ip} locked due to brute force attempts",
                    source_ip=source_ip,
                    user_id=user_id
                )
        
        return True
    
    def monitor_operation(self, operation_type: str, duration: float, 
                         success: bool, metadata: Dict[str, Any] = None):
        """Monitor a cryptographic operation for anomalies."""
        self.anomaly_detector.record_operation(operation_type, duration, success, metadata)
        
        # Check for anomalies
        anomalies = self.anomaly_detector.detect_anomalies()
        for anomaly in anomalies:
            self.report_security_event(
                SecurityEventType.UNUSUAL_ACTIVITY,
                anomaly['severity'],
                anomaly['description'],
                metadata=anomaly['metadata']
            )
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status and metrics."""
        uptime = time.time() - self.metrics['start_time']
        
        return {
            'uptime_seconds': uptime,
            'total_security_events': self.metrics['total_events'],
            'events_by_type': dict(self.metrics['events_by_type']),
            'events_by_threat_level': dict(self.metrics['events_by_threat_level']),
            'blocked_ips_count': len(self.metrics['blocked_ips']),
            'log_integrity_valid': self.secure_logger.verify_log_integrity(),
            'anomaly_detector_baseline_size': len(self.anomaly_detector.baseline_metrics)
        }
    
    def validate_input(self, input_data: Any, expected_type: type, 
                      max_length: Optional[int] = None) -> bool:
        """Validate input data for security."""
        try:
            # Type validation
            if not isinstance(input_data, expected_type):
                self.report_security_event(
                    SecurityEventType.INVALID_INPUT,
                    ThreatLevel.LOW,
                    f"Invalid input type: expected {expected_type}, got {type(input_data)}",
                    metadata={'expected_type': str(expected_type), 'actual_type': str(type(input_data))}
                )
                return False
            
            # Length validation for strings and bytes
            if max_length and hasattr(input_data, '__len__'):
                if len(input_data) > max_length:
                    self.report_security_event(
                        SecurityEventType.INVALID_INPUT,
                        ThreatLevel.MEDIUM,
                        f"Input too long: {len(input_data)} > {max_length}",
                        metadata={'input_length': len(input_data), 'max_length': max_length}
                    )
                    return False
            
            return True
        except Exception as e:
            self.report_security_event(
                SecurityEventType.INVALID_INPUT,
                ThreatLevel.MEDIUM,
                f"Input validation error: {str(e)}",
                metadata={'error': str(e)}
            )
            return False

