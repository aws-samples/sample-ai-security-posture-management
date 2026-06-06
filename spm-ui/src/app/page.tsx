"use client";
import { useEffect, useState } from "react";
import { getDashboard, triggerScan, triggerEvaluation, getFindings, getRuntimeEvents } from "@/lib/api";

export default function DashboardPage() {
  const [data, setData] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [scanning, setScanning] = useState(false);

  const loadAll = () => {
    getDashboard().then(setData).catch(console.error);
    getFindings({ status: "open" }).then(d => setFindings((d.findings || []).slice(0, 5))).catch(console.error);
    getRuntimeEvents(10).then(d => setEvents(d.events || [])).catch(console.error);
  };

  useEffect(() => {
    loadAll();
    const interval = setInterval(loadAll, 15000);
    return () => clearInterval(interval);
  }, []);

  async function handleScan() {
    setScanning(true);
    try {
      await triggerScan();
      await triggerEvaluation();
      const d = await getDashboard();
      setData(d);
      getFindings({ status: "open" }).then(d => setFindings((d.findings || []).slice(0, 5)));
    } finally { setScanning(false); }
  }

  if (!data) return <div className="flex items-center justify-center h-full"><div className="w-8 h-8 rounded-lg bg-gradient-to-br from-red-500 to-orange-600 animate-pulse" /></div>;

  const sev = data.risk_distribution || {};
  const sevTotal = sev.critical + sev.high + sev.medium + sev.low || 1;

  return (
    <div className="max-w-6xl mx-auto px-8 py-8">
      {/* Header */}
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight"><span className="gradient-text">Security Dashboard</span></h1>
          <p className="text-gray-500 text-sm mt-1">AI agent posture overview across {data.total_agents} agents</p>
        </div>
        <button onClick={handleScan} disabled={scanning}
          className="bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 disabled:opacity-50 px-4 py-2 rounded-xl text-sm font-medium transition shadow-lg shadow-red-500/20">
          {scanning ? "Scanning..." : "⚡ Scan & Evaluate"}
        </button>
      </div>

      {/* Pillar Cards */}
      <div className="grid grid-cols-3 gap-3 mb-8">
        <PillarCard icon="🔍" name="Observe" subtitle="Discovery & Inventory"
          stats={[{ label: "Agents", value: data.total_agents }, { label: "Topology Nodes", value: data.topology_nodes }, { label: "Edges", value: data.topology_edges }]}
          color="from-blue-500/20 to-cyan-500/20 border-blue-500/10" />
        <PillarCard icon="📋" name="Govern" subtitle="Posture & Compliance"
          stats={[{ label: "Open Findings", value: data.open_findings }, { label: "Total Findings", value: data.total_findings }, { label: "Rules", value: 10 }]}
          color="from-amber-500/20 to-orange-500/20 border-amber-500/10" />
        <PillarCard icon="🛡" name="Defend" subtitle="Detection & Response"
          stats={[{ label: "Events (24h)", value: data.runtime_events_24h }, { label: "Critical", value: sev.critical }, { label: "High", value: sev.high }]}
          color="from-red-500/20 to-rose-500/20 border-red-500/10" />
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-5 gap-3 mb-8">
        <Stat label="Total Agents" value={data.total_agents} />
        <Stat label="LiteLLM" value={data.by_source?.litellm || 0} />
        <Stat label="Temporal" value={data.by_source?.temporal || 0} />
        <Stat label="Open Findings" value={data.open_findings} accent={data.open_findings > 0} />
        <Stat label="Runtime Events" value={data.runtime_events_24h} />
      </div>

      {/* Risk Distribution + Agent Types */}
      <div className="grid grid-cols-2 gap-4 mb-8">
        <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-6">
          <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-4">Risk Distribution</p>
          <div className="space-y-3">
            <RiskRow label="Critical" count={sev.critical} total={sevTotal} color="bg-red-500" />
            <RiskRow label="High" count={sev.high} total={sevTotal} color="bg-orange-500" />
            <RiskRow label="Medium" count={sev.medium} total={sevTotal} color="bg-yellow-500" />
            <RiskRow label="Low" count={sev.low} total={sevTotal} color="bg-blue-500" />
          </div>
        </div>
        <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-6">
          <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-4">Agent Breakdown</p>
          <div className="space-y-2">
            {Object.entries(data.by_type || {}).map(([k, v]) => (
              <div key={k} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                <div className="flex items-center gap-2">
                  <span className="text-[11px]">{k === "model" ? "🤖" : k === "agent" ? "⚙" : k === "orchestrator" ? "🔄" : "◈"}</span>
                  <span className="text-sm text-gray-300 capitalize">{k}</span>
                </div>
                <span className="text-sm font-mono font-medium">{v as number}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Findings + Runtime Events */}
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <p className="text-[10px] text-gray-500 uppercase tracking-widest">Recent Findings</p>
            <a href="/findings" className="text-[11px] text-red-400 hover:text-red-300">View all →</a>
          </div>
          {findings.length === 0 ? <p className="text-gray-600 text-sm">No open findings</p> : (
            <div className="space-y-2">
              {findings.map(f => (
                <div key={f.finding_id} className="flex items-start gap-2 py-2 border-b border-white/5 last:border-0">
                  <SevDot severity={f.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm truncate">{f.title}</p>
                    <p className="text-[11px] text-gray-600">{f.rule_id}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <p className="text-[10px] text-gray-500 uppercase tracking-widest">Runtime Events</p>
            <a href="/runtime" className="text-[11px] text-red-400 hover:text-red-300">View all →</a>
          </div>
          {events.length === 0 ? <p className="text-gray-600 text-sm">No recent events</p> : (
            <div className="space-y-2">
              {events.map(e => (
                <div key={e.event_id} className="flex items-start gap-2 py-2 border-b border-white/5 last:border-0">
                  <SevDot severity={e.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm truncate">{e.event_type}</p>
                    <p className="text-[11px] text-gray-600">{e.timestamp?.slice(0, 19)}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function PillarCard({ icon, name, subtitle, stats, color }: { icon: string; name: string; subtitle: string; stats: { label: string; value: number }[]; color: string }) {
  return (
    <div className={`bg-gradient-to-br ${color} border rounded-2xl p-5`}>
      <div className="flex items-center gap-2.5 mb-3">
        <span className="text-xl">{icon}</span>
        <div>
          <p className="font-semibold text-[15px]">{name}</p>
          <p className="text-[10px] text-gray-500 uppercase tracking-widest">{subtitle}</p>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-2">
        {stats.map(s => (
          <div key={s.label} className="bg-black/20 rounded-xl p-2.5 text-center">
            <p className="text-lg font-bold">{s.value}</p>
            <p className="text-[10px] text-gray-500">{s.label}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-4">
      <p className="text-[11px] text-gray-500 uppercase tracking-wider">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${accent ? "text-red-400" : ""}`}>{value}</p>
    </div>
  );
}

function RiskRow({ label, count, total, color }: { label: string; count: number; total: number; color: string }) {
  const pct = Math.round((count / total) * 100);
  return (
    <div>
      <div className="flex justify-between text-sm mb-1">
        <span className="text-gray-400">{label}</span>
        <span className="font-mono">{count} <span className="text-gray-600 text-xs">({pct}%)</span></span>
      </div>
      <div className="w-full bg-white/5 rounded-full h-1.5">
        <div className={`${color} h-1.5 rounded-full transition-all`} style={{ width: `${Math.max(pct, 2)}%` }} />
      </div>
    </div>
  );
}

function SevDot({ severity }: { severity: string }) {
  const c: Record<string, string> = { critical: "bg-red-500", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-blue-500" };
  return <span className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${c[severity] || "bg-gray-500"}`} />;
}
