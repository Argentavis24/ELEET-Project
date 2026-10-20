import React, { useState, useEffect } from 'react';
import { 
  Database, UploadCloud, Play, Link2, CheckCircle2, 
  AlertTriangle, ShieldAlert, Filter, FileCode, RefreshCw, 
  Layers, HardDrive, ArrowRight, ShieldCheck, Terminal 
} from 'lucide-react';
import { api } from '../services/api';
import type { DatabaseFile, ScanReport, AttachResult } from '../types';

interface DatabaseScannerProps {
  onScanCompleted?: () => void;
  onAttachedSuccessfully?: () => void;
}

export const DatabaseScanner: React.FC<DatabaseScannerProps> = ({
  onScanCompleted,
  onAttachedSuccessfully
}) => {
  const [databases, setDatabases] = useState<DatabaseFile[]>([]);
  const [selectedFile, setSelectedFile] = useState<string>('');
  const [selectedTable, setSelectedTable] = useState<string>('');
  const [tablesMetadata, setTablesMetadata] = useState<Record<string, any>>({});
  
  // Filter states
  const [protocolFilter, setProtocolFilter] = useState<string>('');
  const [portFilter, setPortFilter] = useState<string>('');
  const [ipFilter, setIpFilter] = useState<string>('');
  const [minPackets, setMinPackets] = useState<string>('');
  const [minBytes, setMinBytes] = useState<string>('');
  const [scanLimit, setScanLimit] = useState<number>(1000);
  
  // Execution states
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isAttaching, setIsAttaching] = useState<boolean>(false);
  
  const [scanReport, setScanReport] = useState<ScanReport | null>(null);
  const [attachResult, setAttachResult] = useState<AttachResult | null>(null);
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadDatabases = async () => {
    try {
      const res = await api.getDatabaseFiles();
      setDatabases(res.databases);
      if (res.databases.length > 0 && !selectedFile) {
        setSelectedFile(res.databases[0].filename);
      }
    } catch (e: any) {
      console.error('Failed to load database files', e);
    }
  };

  useEffect(() => {
    loadDatabases();
  }, []);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    setStatusMessage(null);
    try {
      const res = await api.uploadDatabaseFile(file);
      setStatusMessage({ type: 'success', text: `Uploaded ${file.name} successfully.` });
      await loadDatabases();
      setSelectedFile(res.filename);
      setTablesMetadata(res.tables || {});
      const tableNames = Object.keys(res.tables || {});
      if (tableNames.length > 0) {
        setSelectedTable(tableNames[0]);
      }
    } catch (err: any) {
      setStatusMessage({ type: 'error', text: err.message });
    } finally {
      setIsUploading(false);
    }
  };

  const handleGenerateSample = async () => {
    setIsGenerating(true);
    setStatusMessage(null);
    try {
      const res = await api.generateSampleDatabase();
      setStatusMessage({ type: 'success', text: `Generated sample network telemetry DB: ${res.filename}` });
      await loadDatabases();
      setSelectedFile(res.filename);
      setTablesMetadata(res.tables || {});
      const tableNames = Object.keys(res.tables || {});
      if (tableNames.length > 0) {
        setSelectedTable(tableNames[0]);
      }
    } catch (err: any) {
      setStatusMessage({ type: 'error', text: err.message });
    } finally {
      setIsGenerating(false);
    }
  };

  const handleRunScan = async () => {
    if (!selectedFile) {
      setStatusMessage({ type: 'error', text: 'Please select or upload a database file first.' });
      return;
    }
    const targetTable = selectedTable || (Object.keys(tablesMetadata)[0]) || 'external_network_traffic';
    
    setIsScanning(true);
    setStatusMessage(null);
    setAttachResult(null);

    try {
      const report = await api.scanDatabase({
        filename: selectedFile,
        table_name: targetTable,
        protocol_filter: protocolFilter || undefined,
        port_filter: portFilter ? parseInt(portFilter) : undefined,
        ip_filter: ipFilter || undefined,
        min_packets: minPackets ? parseInt(minPackets) : undefined,
        min_bytes: minBytes ? parseInt(minBytes) : undefined,
        limit: scanLimit
      });
      setScanReport(report);
      setStatusMessage({ 
        type: 'success', 
        text: `Scan finished! Evaluated ${report.total_rows_scanned} records. Identified ${report.threats_detected_count} threat violations.` 
      });
      if (onScanCompleted) onScanCompleted();
    } catch (err: any) {
      setStatusMessage({ type: 'error', text: err.message });
    } finally {
      setIsScanning(false);
    }
  };

  const handleAttachToDBMS = async () => {
    if (!selectedFile) return;
    const targetTable = selectedTable || (Object.keys(tablesMetadata)[0]) || 'external_network_traffic';

    setIsAttaching(true);
    setStatusMessage(null);
    try {
      const res = await api.attachDatabase(selectedFile, targetTable);
      setAttachResult(res);
      setStatusMessage({ 
        type: 'success', 
        text: res.message 
      });
      if (onAttachedSuccessfully) onAttachedSuccessfully();
    } catch (err: any) {
      setStatusMessage({ type: 'error', text: err.message });
    } finally {
      setIsAttaching(false);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Database className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-wide">
                Database Security Scanner & DBMS Ingestion
              </h2>
              <p className="text-xs text-slate-400">
                Inspect external SQLite databases, filter by protocol/port/IP, evaluate rows against NIDS rules & ML models, and attach directly to the primary DBMS.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleGenerateSample}
              disabled={isGenerating}
              className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 font-semibold text-xs flex items-center gap-2 transition-colors"
            >
              <HardDrive className="w-4 h-4" />
              {isGenerating ? 'Generating...' : 'Generate Sample Audit DB'}
            </button>
            <button
              onClick={loadDatabases}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              title="Refresh database files"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Status notification */}
        {statusMessage && (
          <div className={`mt-4 p-3 rounded-lg border text-xs font-mono flex items-center gap-2 ${
            statusMessage.type === 'success'
              ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
              : 'bg-rose-950/60 border-rose-800 text-rose-300'
          }`}>
            {statusMessage.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            )}
            <span>{statusMessage.text}</span>
          </div>
        )}
      </div>

      {/* Database File Upload & Selector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Upload Zone (4 cols) */}
        <div className="lg:col-span-5 p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200 mb-2 flex items-center gap-2">
              <UploadCloud className="w-4 h-4 text-cyan-400" />
              Upload Database File
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Select any local SQLite database (<code className="text-cyan-300">.db</code>, <code className="text-cyan-300">.sqlite</code>, <code className="text-cyan-300">.sqlite3</code>) to scan network flows.
            </p>

            <label className="border-2 border-dashed border-slate-700 hover:border-cyan-500 rounded-xl p-6 flex flex-col items-center justify-center cursor-pointer transition-colors bg-slate-950/40">
              <UploadCloud className="w-8 h-8 text-slate-400 mb-2" />
              <span className="text-xs font-semibold text-slate-200">
                {isUploading ? 'Uploading & inspecting schema...' : 'Click or drop database file here'}
              </span>
              <span className="text-[10px] text-slate-500 mt-1 font-mono">
                Supports SQLite v3 databases
              </span>
              <input
                type="file"
                accept=".db,.sqlite,.sqlite3"
                onChange={handleFileUpload}
                disabled={isUploading}
                className="hidden"
              />
            </label>
          </div>

          {/* Quick Stats of available files */}
          <div className="mt-4 pt-3 border-t border-slate-800 text-xs text-slate-400 flex items-center justify-between font-mono">
            <span>Available Databases: {databases.length}</span>
            <span className="text-cyan-400">SQLite Engine Ready</span>
          </div>
        </div>

        {/* Database Selection & Target Table (7 cols) */}
        <div className="lg:col-span-7 p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200 mb-2 flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-400" />
              Target Database & Table Selection
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Select which uploaded database and table to scan with the NIDS heuristic rules and ML anomaly engine.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Database File</label>
                <select
                  value={selectedFile}
                  onChange={(e) => setSelectedFile(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                >
                  {databases.length === 0 ? (
                    <option value="">No databases uploaded</option>
                  ) : (
                    databases.map((db) => (
                      <option key={db.filename} value={db.filename}>
                        {db.filename} ({formatBytes(db.size_bytes)})
                      </option>
                    ))
                  )}
                </select>
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Target Table Name</label>
                <input
                  type="text"
                  value={selectedTable}
                  onChange={(e) => setSelectedTable(e.target.value)}
                  placeholder="e.g. external_network_traffic"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            {/* Quick table hint */}
            <div className="mt-3 p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 text-[11px] text-slate-400 font-mono flex items-center justify-between">
              <span>Auto-detects: src_ip, dst_ip, port, protocol, packets, bytes, duration</span>
              <span className="text-emerald-400">Schema Verified</span>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex justify-end gap-2">
            <button
              onClick={handleRunScan}
              disabled={isScanning || !selectedFile}
              className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-xs flex items-center gap-2 transition-colors shadow-lg shadow-cyan-950/50"
            >
              <Play className="w-3.5 h-3.5 fill-white" />
              {isScanning ? 'Executing Security Scan...' : 'Scan Database Now'}
            </button>
          </div>
        </div>
      </div>

      {/* Advanced Scan Filters Bar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
          <Filter className="w-4 h-4 text-cyan-400" />
          Ingestion & Scan Query Filters
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3 text-xs">
          <div>
            <label className="block text-slate-400 mb-1">Protocol Filter</label>
            <select
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-slate-300 font-mono"
            >
              <option value="">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ARP">ARP</option>
              <option value="ICMP">ICMP</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Port Match</label>
            <input
              type="number"
              value={portFilter}
              onChange={(e) => setPortFilter(e.target.value)}
              placeholder="e.g. 80, 443, 22, 4444"
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-slate-300 font-mono"
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">IP Search</label>
            <input
              type="text"
              value={ipFilter}
              onChange={(e) => setIpFilter(e.target.value)}
              placeholder="e.g. 192.168, 10.0"
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-slate-300 font-mono"
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Min Packets Threshold</label>
            <input
              type="number"
              value={minPackets}
              onChange={(e) => setMinPackets(e.target.value)}
              placeholder="e.g. 100"
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-slate-300 font-mono"
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Max Scan Limit</label>
            <select
              value={scanLimit}
              onChange={(e) => setScanLimit(parseInt(e.target.value))}
              className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-slate-300 font-mono"
            >
              <option value={200}>200 rows</option>
              <option value={500}>500 rows</option>
              <option value={1000}>1,000 rows</option>
              <option value={3000}>3,000 rows</option>
            </select>
          </div>
        </div>
      </div>

      {/* Scan Results & Findings Section */}
      {scanReport && (
        <div className="space-y-4 animate-fade-in">
          {/* Summary Badges and Attach Action Header */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-3">
                <span className="text-base font-bold text-white tracking-wide">
                  Forensic Scan Report: {scanReport.scanned_database}
                </span>
                <span className="text-xs px-2.5 py-0.5 rounded-full font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
                  {scanReport.total_rows_scanned} Rows Evaluated
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                Identified {scanReport.threats_detected_count} threat vectors violating security heuristics or ML baselines.
              </p>
            </div>

            {/* Attach to Active DBMS Action Button */}
            <button
              onClick={handleAttachToDBMS}
              disabled={isAttaching}
              className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold text-xs flex items-center gap-2 transition-colors shadow-lg shadow-emerald-950/40"
            >
              <Link2 className="w-4 h-4" />
              {isAttaching ? 'Attaching & Merging...' : 'Attach & Merge to Active DBMS'}
            </button>
          </div>

          {/* Severity Counters */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900/40 text-rose-300">
              <span className="text-[10px] font-bold uppercase tracking-wider block text-rose-400">Critical Threats</span>
              <span className="text-xl font-bold font-mono">{scanReport.severity_summary.Critical || 0}</span>
            </div>
            <div className="p-3 rounded-lg bg-orange-950/40 border border-orange-900/40 text-orange-300">
              <span className="text-[10px] font-bold uppercase tracking-wider block text-orange-400">High Priority</span>
              <span className="text-xl font-bold font-mono">{scanReport.severity_summary.High || 0}</span>
            </div>
            <div className="p-3 rounded-lg bg-yellow-950/40 border border-yellow-900/40 text-yellow-300">
              <span className="text-[10px] font-bold uppercase tracking-wider block text-yellow-400">Medium Priority</span>
              <span className="text-xl font-bold font-mono">{scanReport.severity_summary.Medium || 0}</span>
            </div>
            <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-900/40 text-cyan-300">
              <span className="text-[10px] font-bold uppercase tracking-wider block text-cyan-400">Low / Anomaly</span>
              <span className="text-xl font-bold font-mono">{scanReport.severity_summary.Low || 0}</span>
            </div>
          </div>

          {/* Threat Findings Table */}
          <div className="rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm overflow-hidden shadow-xl">
            <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Detected Threat Signatures in Database
              </h3>
              <span className="text-xs font-mono text-slate-400">
                Top {scanReport.threat_findings.length} findings
              </span>
            </div>

            <div className="overflow-x-auto max-h-96">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800 sticky top-0">
                  <tr>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Rule Violation</th>
                    <th className="py-2.5 px-3">Threat Source</th>
                    <th className="py-2.5 px-3">Target Host</th>
                    <th className="py-2.5 px-2">Port</th>
                    <th className="py-2.5 px-2">Proto</th>
                    <th className="py-2.5 px-2">Risk</th>
                    <th className="py-2.5 px-3">Detection Explanation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {scanReport.threat_findings.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                        <ShieldCheck className="w-6 h-6 mx-auto mb-1 text-emerald-400 opacity-60" />
                        No threat violations identified in scanned records.
                      </td>
                    </tr>
                  ) : (
                    scanReport.threat_findings.map((f, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${
                            f.severity === 'Critical' 
                              ? 'bg-rose-950 text-rose-400 border-rose-800' 
                              : (f.severity === 'High' ? 'bg-orange-950 text-orange-400 border-orange-800' : 'bg-yellow-950 text-yellow-400 border-yellow-800')
                          }`}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-semibold text-white font-sans">
                          {f.rule_name}
                        </td>
                        <td className="py-2.5 px-3 text-rose-400 font-bold">
                          {f.src_ip}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {f.dst_ip}
                        </td>
                        <td className="py-2.5 px-2 text-cyan-400">
                          {f.dst_port}
                        </td>
                        <td className="py-2.5 px-2 text-slate-400">
                          {f.protocol}
                        </td>
                        <td className="py-2.5 px-2 font-bold text-rose-400">
                          {Math.round(f.risk_score * 100)}%
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 font-sans text-[11px] truncate max-w-sm" title={f.explanation}>
                          {f.explanation}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
