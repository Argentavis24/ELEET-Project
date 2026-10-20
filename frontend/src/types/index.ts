export interface NetworkFlow {
  id: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  packet_count: number;
  byte_count: number;
  duration: number;
  classification: string;
  risk_score: number;
  alert_reason?: string;
  mac_address?: string;
  is_simulated: boolean;
}

export interface Alert {
  id: number;
  timestamp: string;
  rule_name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  evidence: string;
  explanation: string;
  recommended_action: string;
  status: 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  notes?: string;
  flow_id?: number;
  updated_at: string;
}

export interface DashboardMetrics {
  total_flows: number;
  active_alerts: number;
  critical_alerts: number;
  blocked_ips_count: number;
  throughput_kbps: number;
  packets_per_sec: number;
  system_status: {
    engine: string;
    ml_anomaly_detector: string;
    active_rules_count: number;
    quarantined_ips_count: number;
    database: string;
  };
}

export interface ProtocolStat {
  protocol: string;
  count: number;
}

export interface SeverityStat {
  severity: string;
  count: number;
}

export interface TrafficPoint {
  time: string;
  bytes: number;
  packets: number;
  threats: number;
  flows: number;
}

export interface TopSrcIP {
  ip: string;
  flows: number;
  bytes: number;
  max_risk: number;
  is_blocked: boolean;
}

export interface DashboardCharts {
  protocol_distribution: ProtocolStat[];
  alert_severity: SeverityStat[];
  traffic_over_time: TrafficPoint[];
  top_source_ips: TopSrcIP[];
  top_destination_ips: { ip: string; flows: number }[];
}

export interface User {
  id: number;
  username: string;
  full_name?: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface QuarantinedIP {
  id: number;
  ip_address: string;
  reason: string;
  blocked_at: string;
  blocked_by: string;
  is_active: boolean;
}

export interface SimulationStatus {
  is_running: boolean;
  rate_flows_per_second: number;
  attack_probability: number;
  total_simulated_flows: number;
  total_simulated_alerts: number;
  active_scenarios: string[];
}

export interface DatabaseFile {
  filename: string;
  size_bytes: number;
  created_at: string;
  file_path: string;
}

export interface TableColumn {
  cid: number;
  name: string;
  type: string;
  notnull: boolean;
  pk: boolean;
}

export interface TableDetail {
  columns: TableColumn[];
  row_count: number;
  probable_mapping: Record<string, string | null>;
}

export interface ThreatFinding {
  rule_name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  classification: string;
  risk_score: number;
  explanation: string;
  recommended_action: string;
  timestamp: string;
}

export interface ScanReport {
  status: string;
  scanned_database: string;
  table_name: string;
  total_rows_scanned: number;
  threats_detected_count: number;
  severity_summary: Record<string, number>;
  classification_summary: Record<string, number>;
  threat_findings: ThreatFinding[];
  scanned_flows_sample: any[];
}

export interface AttachResult {
  status: string;
  message: string;
  imported_flows: number;
  imported_alerts: number;
  attached_database: string;
}
