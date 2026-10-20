import time
from collections import defaultdict, deque
from typing import Dict, Deque, Tuple, Optional, Set
import threading

class FlowRecord:
    __slots__ = ('timestamp', 'dst_ip', 'dst_port', 'protocol', 'packet_count', 'byte_count')

    def __init__(self, timestamp: float, dst_ip: str, dst_port: int, protocol: str, packet_count: int, byte_count: int):
        self.timestamp = timestamp
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.packet_count = packet_count
        self.byte_count = byte_count

class SlidingWindow:
    def __init__(self, default_ttl: float = 60.0):
        self.default_ttl = default_ttl
        self.lock = threading.Lock()
        
        # src_ip -> deque of FlowRecord
        self.src_flows: Dict[str, Deque[FlowRecord]] = defaultdict(deque)
        
        # dst_ip -> deque of FlowRecord
        self.dst_flows: Dict[str, Deque[FlowRecord]] = defaultdict(deque)
        
        # IP -> known MAC mapping for ARP spoofing
        self.arp_table: Dict[str, str] = {}
        
        # Deduplication tracker to avoid alert storm for ongoing attacks
        # (src_ip, rule_name) -> last_alert_time
        self.last_alert_times: Dict[Tuple[str, str], float] = {}

    def add_flow(self, timestamp: float, src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                 protocol: str, packet_count: int, byte_count: int, mac_address: Optional[str] = None) -> None:
        with self.lock:
            record = FlowRecord(timestamp, dst_ip, dst_port, protocol, packet_count, byte_count)
            self.src_flows[src_ip].append(record)
            self.dst_flows[dst_ip].append(record)
            
            # Prune old records
            self._prune(timestamp)

    def _prune(self, current_time: float):
        cutoff = current_time - self.default_ttl
        # Prune src_flows
        keys_to_remove = []
        for ip, queue in self.src_flows.items():
            while queue and queue[0].timestamp < cutoff:
                queue.popleft()
            if not queue:
                keys_to_remove.append(ip)
        for ip in keys_to_remove:
            del self.src_flows[ip]

        # Prune dst_flows
        keys_to_remove = []
        for ip, queue in self.dst_flows.items():
            while queue and queue[0].timestamp < cutoff:
                queue.popleft()
            if not queue:
                keys_to_remove.append(ip)
        for ip in keys_to_remove:
            del self.dst_flows[ip]

        # Prune alert throttle cache
        throttle_cutoff = current_time - 15.0
        stale_alert_keys = [k for k, t in self.last_alert_times.items() if t < throttle_cutoff]
        for k in stale_alert_keys:
            del self.last_alert_times[k]

    def get_src_records(self, src_ip: str, window_seconds: float, current_time: float):
        with self.lock:
            cutoff = current_time - window_seconds
            queue = self.src_flows.get(src_ip, deque())
            return [r for r in queue if r.timestamp >= cutoff]

    def get_dst_records(self, dst_ip: str, window_seconds: float, current_time: float):
        with self.lock:
            cutoff = current_time - window_seconds
            queue = self.dst_flows.get(dst_ip, deque())
            return [r for r in queue if r.timestamp >= cutoff]

    def check_arp_conflict(self, ip: str, mac: Optional[str]) -> Tuple[bool, Optional[str]]:
        if not mac:
            return False, None
        with self.lock:
            existing_mac = self.arp_table.get(ip)
            if existing_mac and existing_mac.lower() != mac.lower():
                return True, existing_mac
            elif not existing_mac:
                self.arp_table[ip] = mac
            return False, None

    def should_suppress_alert(self, src_ip: str, rule_name: str, current_time: float, cooldown: float = 8.0) -> bool:
        with self.lock:
            key = (src_ip, rule_name)
            last_time = self.last_alert_times.get(key)
            if last_time and (current_time - last_time) < cooldown:
                return True
            self.last_alert_times[key] = current_time
            return False

    def clear(self):
        with self.lock:
            self.src_flows.clear( )
            self.dst_flows.clear()
            self.arp_table.clear()
            self.last_alert_times.clear()
