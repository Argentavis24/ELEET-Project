import type { NetworkFlow, Alert } from '../types';

type FlowHandler = (flow: NetworkFlow) => void;
type AlertHandler = (alert: Alert) => void;
type StatusHandler = (isConnected: boolean) => void;

class RealtimeThreatSocket {
  private socket: WebSocket | null = null;
  private flowListeners: Set<FlowHandler> = new Set();
  private alertListeners: Set<AlertHandler> = new Set();
  private statusListeners: Set<StatusHandler> = new Set();
  private isConnected: boolean = false;
  private isPaused: boolean = false;
  private reconnectTimeout: number | null = null;
  private pingInterval: number | null = null;

  connect() {
    if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws`;

    try {
      this.socket = new WebSocket(wsUrl);

      this.socket.onopen = () => {
        this.isConnected = true;
        this.notifyStatus(true);
        this.startHeartbeat();
      };

      this.socket.onmessage = (event) => {
        if (this.isPaused) return;

        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'FLOW' && msg.data) {
            this.flowListeners.forEach(listener => listener(msg.data));
          } else if (msg.type === 'ALERT' && msg.data) {
            this.alertListeners.forEach(listener => listener(msg.data));
          }
        } catch (e) {
          console.error('Error parsing WebSocket message', e);
        }
      };

      this.socket.onclose = () => {
        this.isConnected = false;
        this.notifyStatus(false);
        this.stopHeartbeat();
        this.scheduleReconnect();
      };

      this.socket.onerror = () => {
        if (this.socket) {
          this.socket.close();
        }
      };
    } catch (err) {
      this.scheduleReconnect();
    }
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    this.pingInterval = window.setInterval(() => {
      if (this.socket && this.socket.readyState === WebSocket.OPEN) {
        this.socket.send(JSON.stringify({ action: 'ping' }));
      }
    }, 15000);
  }

  private stopHeartbeat() {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimeout) return;
    this.reconnectTimeout = window.setTimeout(() => {
      this.reconnectTimeout = null;
      this.connect();
    }, 3000);
  }

  private notifyStatus(status: boolean) {
    this.statusListeners.forEach(listener => listener(status));
  }

  onFlow(handler: FlowHandler): () => void {
    this.flowListeners.add(handler);
    return () => this.flowListeners.delete(handler);
  }

  onAlert(handler: AlertHandler): () => void {
    this.alertListeners.add(handler);
    return () => this.alertListeners.delete(handler);
  }

  onStatusChange(handler: StatusHandler): () => void {
    this.statusListeners.add(handler);
    handler(this.isConnected);
    return () => this.statusListeners.delete(handler);
  }

  pause() {
    this.isPaused = true;
  }

  resume() {
    this.isPaused = false;
  }

  getIsPaused() {
    return this.isPaused;
  }

  disconnect() {
    this.stopHeartbeat();
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }
}

export const realtimeSocket = new RealtimeThreatSocket();
