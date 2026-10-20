import type { 
  NetworkFlow, Alert, DashboardMetrics, DashboardCharts, 
  QuarantinedIP, SimulationStatus, User, DatabaseFile, ScanReport, AttachResult 
} from '../types';

const API_BASE = '/api/v1';

function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem('nids_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export const api = {
  // Authentication
  async login(username: string, password: string): Promise<{ access_token: string; user: User }> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to authenticate');
    }
    return res.json();
  },

  async getCurrentUser(): Promise<User | null> {
    const res = await fetch(`${API_BASE}/auth/me`, {
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) return null;
    return res.json();
  },

  // Dashboard
  async getMetrics(): Promise<DashboardMetrics> {
    const res = await fetch(`${API_BASE}/dashboard/metrics`, {
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to fetch dashboard metrics');
    return res.json();
  },

  async getCharts(): Promise<DashboardCharts> {
    const res = await fetch(`${API_BASE}/dashboard/charts`, {
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to fetch dashboard charts');
    return res.json();
  },

  // Flows
  async getFlows(params: {
    limit?: number;
    offset?: number;
    src_ip?: string;
    dst_ip?: string;
    port?: number;
    protocol?: string;
    classification?: string;
    min_risk?: number;
    search?: string;
    sort_by?: string;
    sort_desc?: boolean;
  }): Promise<{ total: number; flows: NetworkFlow[]; page: number; limit: number }> {
    const query = new URLSearchParams();
    if (params.limit) query.append('limit', params.limit.toString());
    if (params.offset !== undefined) query.append('offset', params.offset.toString());
    if (params.src_ip) query.append('src_ip', params.src_ip);
    if (params.dst_ip) query.append('dst_ip', params.dst_ip);
    if (params.port) query.append('port', params.port.toString());
    if (params.protocol) query.append('protocol', params.protocol);
    if (params.classification) query.append('classification', params.classification);
    if (params.min_risk !== undefined) query.append('min_risk', params.min_risk.toString());
    if (params.search) query.append('search', params.search);
    if (params.sort_by) query.append('sort_by', params.sort_by);
    if (params.sort_desc !== undefined) query.append('sort_desc', params.sort_desc.toString());

    const res = await fetch(`${API_BASE}/flows?${query.toString()}`, {
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to fetch flows');
    return res.json();
  },

  getFlowsExportUrl(params: {
    src_ip?: string;
    dst_ip?: string;
    port?: number;
    protocol?: string;
    classification?: string;
    min_risk?: number;
    limit?: number;
  }): string {
    const query = new URLSearchParams();
    if (params.src_ip) query.append('src_ip', params.src_ip);
    if (params.dst_ip) query.append('dst_ip', params.dst_ip);
    if (params.port) query.append('port', params.port.toString());
    if (params.protocol) query.append('protocol', params.protocol);
    if (params.classification) query.append('classification', params.classification);
    if (params.min_risk !== undefined) query.append('min_risk', params.min_risk.toString());
    if (params.limit) query.append('limit', params.limit.toString());
    return `${API_BASE}/flows/export?${query.toString()}`;
  },

  // Alerts
  async getAlerts(params: {
    limit?: number;
    offset?: number;
    severity?: string;
    status?: string;
    rule_name?: string;
    src_ip?: string;
    search?: string;
  }): Promise<{ total: number; alerts: Alert[]; page: number; limit: number }> {
    const query = new URLSearchParams();
    if (params.limit) query.append('limit', params.limit.toString());
    if (params.offset !== undefined) query.append('offset', params.offset.toString());
    if (params.severity) query.append('severity', params.severity);
    if (params.status) query.append('status', params.status);
    if (params.rule_name) query.append('rule_name', params.rule_name);
    if (params.src_ip) query.append('src_ip', params.src_ip);
    if (params.search) query.append('search', params.search);

    const res = await fetch(`${API_BASE}/alerts?${query.toString()}`, {
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to fetch alerts');
    return res.json();
  },

  async getAlert(alertId: number): Promise<Alert> {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`, {
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to fetch alert details');
    return res.json();
  },

  async updateAlert(alertId: number, data: { status?: string; notes?: string }): Promise<Alert> {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error('Failed to update alert');
    return res.json();
  },

  async quarantineFromAlert(alertId: number): Promise<{ status: string; message: string; ip_address: string }> {
    const res = await fetch(`${API_BASE}/alerts/${alertId}/quarantine`, {
      method: 'POST',
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to quarantine alert source');
    return res.json();
  },

  // Quarantine
  async getQuarantineList(): Promise<{ total: number; blocked_ips: QuarantinedIP[] }> {
    const res = await fetch(`${API_BASE}/quarantine`, {
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to fetch quarantined IPs');
    return res.json();
  },

  async blockIP(ip_address: string, reason: string): Promise<QuarantinedIP> {
    const res = await fetch(`${API_BASE}/quarantine`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ ip_address, reason })
    });
    if (!res.ok) throw new Error('Failed to block IP');
    return res.json();
  },

  async unblockIP(ip_address: string): Promise<{ status: string; message: string }> {
    const res = await fetch(`${API_BASE}/quarantine/${encodeURIComponent(ip_address)}`, {
      method: 'DELETE',
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to unblock IP');
    return res.json();
  },

  // Simulation
  async getSimulationStatus(): Promise<SimulationStatus> {
    const res = await fetch(`${API_BASE}/simulation/status`, {
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to fetch simulation status');
    return res.json();
  },

  async startSimulation(): Promise<SimulationStatus> {
    const res = await fetch(`${API_BASE}/simulation/start`, {
      method: 'POST',
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to start simulation');
    return res.json();
  },

  async stopSimulation(): Promise<SimulationStatus> {
    const res = await fetch(`${API_BASE}/simulation/stop`, {
      method: 'POST',
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to stop simulation');
    return res.json();
  },

  async configureSimulation(config: Partial<SimulationStatus>): Promise<SimulationStatus> {
    const res = await fetch(`${API_BASE}/simulation/configure`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify(config)
    });
    if (!res.ok) throw new Error('Failed to configure simulation');
    return res.json();
  },

  async triggerScenario(scenario: string, target_ip?: string): Promise<{
    status: string;
    scenario: string;
    flows_generated: number;
    alerts_triggered: number;
    alerts: any[];
  }> {
    const res = await fetch(`${API_BASE}/simulation/trigger`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ scenario, target_ip })
    });
    if (!res.ok) throw new Error('Failed to trigger attack scenario');
    return res.json();
  },

  // Database Scanner & DBMS Attachment
  async getDatabaseFiles(): Promise<{ databases: DatabaseFile[] }> {
    const res = await fetch(`${API_BASE}/dbms/databases`, {
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to fetch uploaded database files');
    return res.json();
  },

  async uploadDatabaseFile(file: File): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/dbms/upload`, {
      method: 'POST',
      headers: { ...getAuthHeader() },
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to upload database file');
    }
    return res.json();
  },

  async generateSampleDatabase(): Promise<any> {
    const res = await fetch(`${API_BASE}/dbms/generate-sample`, {
      method: 'POST',
      headers: { ...getAuthHeader() }
    });
    if (!res.ok) throw new Error('Failed to generate sample database');
    return res.json();
  },

  async scanDatabase(params: {
    filename: string;
    table_name: string;
    protocol_filter?: string;
    min_packets?: number;
    min_bytes?: number;
    port_filter?: number;
    ip_filter?: string;
    limit?: number;
  }): Promise<ScanReport> {
    const formData = new FormData();
    formData.append('filename', params.filename);
    formData.append('table_name', params.table_name);
    if (params.protocol_filter) formData.append('protocol_filter', params.protocol_filter);
    if (params.min_packets) formData.append('min_packets', params.min_packets.toString());
    if (params.min_bytes) formData.append('min_bytes', params.min_bytes.toString());
    if (params.port_filter) formData.append('port_filter', params.port_filter.toString());
    if (params.ip_filter) formData.append('ip_filter', params.ip_filter);
    if (params.limit) formData.append('limit', params.limit.toString());

    const res = await fetch(`${API_BASE}/dbms/scan`, {
      method: 'POST',
      headers: { ...getAuthHeader() },
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to execute database scan');
    }
    return res.json();
  },

  async attachDatabase(filename: string, table_name: string): Promise<AttachResult> {
    const formData = new FormData();
    formData.append('filename', filename);
    formData.append('table_name', table_name);

    const res = await fetch(`${API_BASE}/dbms/attach`, {
      method: 'POST',
      headers: { ...getAuthHeader() },
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to attach database to active DBMS');
    }
    return res.json();
  }
};
