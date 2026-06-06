"use client";
import { useEffect, useState } from "react";
import { getFindings, acknowledgeFinding, resolveFinding, triggerEvaluation, remediate } from "@/lib/api";

const SEV_STYLES: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/20",
};
const STATUS_STYLES: Record<string, string> = {
  open: "bg-red-500/10 text-red-300 border-red-500/20",
  acknowledged: "bg-yellow-500/10 text-yellow-300 border-yellow-500/20",
  resolved: "bg-emerald-500/10 text-emerald-300 border-emerald-500/20",
};

export default function FindingsPage() {
  const [findings, setFindings] = useState<any[]>([]);
  const [filter, setFilter] = useState("");
  const [evaluating, setEvaluating] = useState(false);

  const load = () => getFindings().then(d => setFindings(d.findings || [])).catch(console.error);
  useEffect(() => {
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  async function handleEvaluate() {
    setEvaluating(true);
    try { await triggerEvaluation(); await load(); } finally { setEvaluating(false); }
  }

  const filtered = findings.filter(f => !filter || f.severity === filter || f.status === filter);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach(f => { if (f.severity in counts) counts[f.severity as keyof typeof counts]++; });

  return (
    <div className="max-w-6xl mx-auto px-8 py-8">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight"><span className="gradient-text">Security Findings</span></h1>
          <p className="text-gray-500 text-sm mt-1">{findings.length} findings from {10} policy rules</p>
        </div>
        <button onClick={handleEvaluate} disabled={evaluating}
          className="bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 disabled:opacity-50 px-4 py-2 rounded-xl text-sm font-medium transition shadow-lg shadow-red-500/20">
          {evaluating ? "Evaluating..." : "⚡ Run Evaluation"}
        </button>
      </div>

      {/* Severity summary */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        {(["critical", "high", "medium", "low"] as const).map(s => (
          <button key={s} onClick={() => setFilter(filter === s ? "" : s)}
            className={`bg-white/[0.03] border rounded-xl p-4 text-left transition ${filter === s ? "border-red-500/30" : "border-white/[0.06] hover:border-white/10"}`}>
            <p className="text-[11px] text-gray-500 uppercase tracking-wider capitalize">{s}</p>
            <p className="text-2xl font-bold mt-1">{counts[s]}</p>
          </button>
        ))}
      </div>

      {/* Filter pills */}
      <div className="flex gap-1 mb-6">
        {["", "open", "acknowledged", "resolved"].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            className={`px-3 py-2 rounded-xl text-[11px] font-medium transition ${
              filter === f ? "bg-red-500/10 text-red-300 border border-red-500/20" : "bg-white/[0.03] text-gray-500 border border-white/[0.06] hover:bg-white/[0.06]"
            }`}>
            {f || "All"}
          </button>
        ))}
      </div>

      {/* Findings list */}
      <div className="space-y-3">
        {filtered.map(f => (
          <div key={f.finding_id} className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-5 hover:border-white/10 transition">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <span className={`text-[10px] px-2.5 py-1 rounded-full font-medium border ${SEV_STYLES[f.severity] || ""}`}>{f.severity}</span>
                  <span className={`text-[10px] px-2.5 py-1 rounded-full font-medium border ${STATUS_STYLES[f.status] || ""}`}>{f.status}</span>
                </div>
                <p className="font-semibold text-[15px]">{f.title}</p>
                <p className="text-sm text-gray-400 mt-1">{f.description}</p>
                <div className="flex items-center gap-4 mt-3">
                  <span className="text-[11px] text-gray-600">Rule: <span className="text-gray-400 font-mono">{f.rule_id}</span></span>
                  <span className="text-[11px] text-gray-600">Agent: <span className="text-gray-400 font-mono">{f.agent_id}</span></span>
                </div>
                {f.remediation && (
                  <div className="mt-3 bg-blue-500/5 border border-blue-500/10 rounded-xl px-4 py-2.5">
                    <p className="text-[11px] text-blue-400">💡 {f.remediation}</p>
                  </div>
                )}
                {f.compliance_frameworks?.length > 0 && (
                  <div className="flex gap-1.5 mt-3">
                    {f.compliance_frameworks.map((c: string) => (
                      <span key={c} className="bg-white/5 border border-white/[0.06] text-[10px] px-2.5 py-1 rounded-lg text-gray-500">{c}</span>
                    ))}
                  </div>
                )}
              </div>
              {f.status === "open" && (
                <div className="flex flex-col gap-2 ml-4">
                  <div className="flex gap-2">
                    <button onClick={() => { acknowledgeFinding(f.finding_id).then(load); }}
                      className="bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 px-3 py-1.5 rounded-xl text-[11px] font-medium hover:bg-yellow-500/20 transition">Acknowledge</button>
                    <button onClick={() => { resolveFinding(f.finding_id).then(load); }}
                      className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 px-3 py-1.5 rounded-xl text-[11px] font-medium hover:bg-emerald-500/20 transition">Resolve</button>
                  </div>
                  {(f.rule_id === "overprivileged_key" || f.rule_id === "unrestricted_model_access") && (
                    <button onClick={() => { if(confirm(`Disable key ${f.agent_id}?`)) remediate("disable_key", f.agent_id, f.title).then(load); }}
                      className="bg-red-500/10 border border-red-500/20 text-red-400 px-3 py-1.5 rounded-xl text-[11px] font-medium hover:bg-red-500/20 transition">🔒 Disable Key</button>
                  )}
                  {f.agent_id?.startsWith("temporal-wf-") && (
                    <button onClick={() => { if(confirm(`Quarantine ${f.agent_id}?`)) remediate("quarantine_agent", f.agent_id, f.title).then(load); }}
                      className="bg-red-500/10 border border-red-500/20 text-red-400 px-3 py-1.5 rounded-xl text-[11px] font-medium hover:bg-red-500/20 transition">🛑 Quarantine Agent</button>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}
        {filtered.length === 0 && (
          <div className="border border-dashed border-white/10 rounded-2xl p-16 text-center">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-red-500/20 to-orange-500/20 flex items-center justify-center mx-auto mb-4"><span className="text-2xl">✦</span></div>
            <p className="text-gray-400 font-medium">{filter ? "No findings match" : "No findings yet"}</p>
            <p className="text-gray-600 text-sm mt-1">Run an evaluation to check agent posture</p>
          </div>
        )}
      </div>
    </div>
  );
}
