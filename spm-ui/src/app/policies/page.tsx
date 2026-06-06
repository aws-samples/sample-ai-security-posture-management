"use client";
import { useEffect, useState } from "react";
import { getPolicies, updatePolicy, createPolicy, deletePolicy } from "@/lib/api";

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<any[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", compliance_framework: "", rule_severity: "medium", rule_description: "" });

  const load = () => getPolicies().then(d => setPolicies(d.policies || [])).catch(console.error);
  useEffect(() => { load(); }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    await createPolicy({
      name: form.name,
      description: form.description,
      compliance_framework: form.compliance_framework,
      rules: form.rule_description ? [{ description: form.rule_description, severity: form.rule_severity }] : [],
      enabled: true,
    });
    setForm({ name: "", description: "", compliance_framework: "", rule_severity: "medium", rule_description: "" });
    setShowCreate(false);
    load();
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this policy?")) return;
    await deletePolicy(id);
    load();
  }

  // Separate custom from defender-config
  const custom = policies.filter(p => p.policy_id !== "defender-config");

  return (
    <div className="max-w-4xl mx-auto px-8 py-8">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight"><span className="gradient-text">Security Policies</span></h1>
          <p className="text-gray-500 text-sm mt-1">Built-in rules + custom policies — evaluation runs automatically every 60s</p>
        </div>
        <button onClick={() => setShowCreate(!showCreate)}
          className="bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 px-4 py-2 rounded-xl text-sm font-medium transition shadow-lg shadow-red-500/20">
          {showCreate ? "Cancel" : "+ Create Policy"}
        </button>
      </div>

      {/* Create Form */}
      {showCreate && (
        <form onSubmit={handleCreate} className="bg-white/[0.02] border border-red-500/20 rounded-2xl p-6 mb-6 space-y-4">
          <p className="text-[10px] text-red-400 uppercase tracking-widest">New Custom Policy</p>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-[11px] text-gray-500 block mb-1">Policy Name *</label>
              <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required
                placeholder="e.g., Max Token Budget Per Request"
                className="w-full bg-white/[0.03] border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-red-500/50 transition placeholder:text-gray-600" />
            </div>
            <div>
              <label className="text-[11px] text-gray-500 block mb-1">Compliance Framework</label>
              <select value={form.compliance_framework} onChange={e => setForm({ ...form, compliance_framework: e.target.value })}
                className="w-full bg-white/[0.03] border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-red-500/50 transition text-gray-300">
                <option value="">None</option>
                <option value="OWASP_LLM_TOP10">OWASP LLM Top 10</option>
                <option value="NIST_AI_RMF">NIST AI RMF</option>
                <option value="MITRE_ATLAS">MITRE ATLAS</option>
              </select>
            </div>
          </div>
          <div>
            <label className="text-[11px] text-gray-500 block mb-1">Description</label>
            <input value={form.description} onChange={e => setForm({ ...form, description: e.target.value })}
              placeholder="What does this policy check for?"
              className="w-full bg-white/[0.03] border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-red-500/50 transition placeholder:text-gray-600" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-[11px] text-gray-500 block mb-1">Rule Description</label>
              <input value={form.rule_description} onChange={e => setForm({ ...form, rule_description: e.target.value })}
                placeholder="e.g., Token count exceeds 10000 per request"
                className="w-full bg-white/[0.03] border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-red-500/50 transition placeholder:text-gray-600" />
            </div>
            <div>
              <label className="text-[11px] text-gray-500 block mb-1">Severity</label>
              <select value={form.rule_severity} onChange={e => setForm({ ...form, rule_severity: e.target.value })}
                className="w-full bg-white/[0.03] border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-red-500/50 transition text-gray-300">
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
          <button type="submit"
            className="bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 px-6 py-2.5 rounded-xl text-sm font-medium transition shadow-lg shadow-red-500/20">
            Create Policy
          </button>
        </form>
      )}

      {/* Built-in rules */}
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-6 mb-6">
        <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-4">Built-in Policy Rules (10)</p>
        <div className="space-y-1">
          {BUILT_IN_RULES.map(r => (
            <div key={r.id} className="flex items-center justify-between py-3 border-b border-white/5 last:border-0">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-medium">{r.name}</p>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full border ${
                    r.type === "config" ? "bg-blue-500/10 text-blue-400 border-blue-500/20" : "bg-purple-500/10 text-purple-400 border-purple-500/20"
                  }`}>{r.type}</span>
                </div>
                <p className="text-[11px] text-gray-600 mt-0.5">{r.desc}</p>
                <div className="flex gap-1.5 mt-1.5">
                  {r.compliance.map(c => (
                    <span key={c} className="bg-white/5 border border-white/[0.06] text-[9px] px-2 py-0.5 rounded-lg text-gray-500">{c}</span>
                  ))}
                </div>
              </div>
              <span className={`text-[10px] px-2.5 py-1 rounded-full font-medium border ${
                r.severity === "high" ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                r.severity === "medium" ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" :
                "bg-blue-500/10 text-blue-400 border-blue-500/20"
              }`}>{r.severity}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Custom policies */}
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-6">
        <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-4">Custom Policies ({custom.length})</p>
        {custom.length === 0 ? (
          <p className="text-gray-600 text-sm">No custom policies yet. Click "Create Policy" to add one.</p>
        ) : (
          <div className="space-y-1">
            {custom.map(p => (
              <div key={p.policy_id} className="flex items-center justify-between py-3 border-b border-white/5 last:border-0">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium">{p.name}</p>
                    {p.compliance_framework && (
                      <span className="bg-white/5 border border-white/[0.06] text-[9px] px-2 py-0.5 rounded-lg text-gray-500">{p.compliance_framework}</span>
                    )}
                  </div>
                  {p.description && <p className="text-[11px] text-gray-600 mt-0.5">{p.description}</p>}
                  {p.rules?.length > 0 && (
                    <div className="mt-1">
                      {p.rules.map((r: any, i: number) => (
                        <span key={i} className="text-[10px] text-gray-500 mr-2">• {r.description} ({r.severity})</span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => { updatePolicy(p.policy_id, !p.enabled).then(load); }}
                    className={`text-[10px] px-2.5 py-1 rounded-full font-medium border transition ${
                      p.enabled ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/20" : "bg-gray-500/10 text-gray-500 border-gray-500/20 hover:bg-gray-500/20"
                    }`}>{p.enabled ? "Enabled" : "Disabled"}</button>
                  <button onClick={() => handleDelete(p.policy_id)}
                    className="text-[11px] text-gray-600 hover:text-red-400 transition">✕</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

const BUILT_IN_RULES = [
  { id: "overprivileged_key", name: "Overprivileged API Key", desc: "Key has no budget limit or model restrictions", severity: "high", type: "config", compliance: ["OWASP_LLM_TOP10", "NIST_AI_RMF"] },
  { id: "missing_guardrails", name: "Missing Model Guardrails", desc: "Model config lacks max_tokens limits", severity: "medium", type: "config", compliance: ["OWASP_LLM_TOP10"] },
  { id: "unrestricted_model_access", name: "Unrestricted Model Access", desc: "Key can access all models with no allowlist", severity: "high", type: "config", compliance: ["NIST_AI_RMF", "MITRE_ATLAS"] },
  { id: "excessive_spend", name: "Excessive Spend", desc: "Key spend exceeds 80% of budget", severity: "medium", type: "config", compliance: ["NIST_AI_RMF"] },
  { id: "stale_agent", name: "Stale Agent", desc: "Workflow type not executed in >7 days", severity: "low", type: "config", compliance: ["NIST_AI_RMF"] },
  { id: "high_retry_rate", name: "High Failure Rate", desc: "Workflow has >10% failure rate", severity: "high", type: "trace", compliance: ["OWASP_LLM_TOP10", "NIST_AI_RMF"] },
  { id: "latency_anomaly", name: "Latency Anomaly", desc: "Agent execution time >2σ from baseline", severity: "medium", type: "trace", compliance: ["MITRE_ATLAS"] },
  { id: "excessive_llm_calls", name: "Excessive LLM Calls", desc: "More LLM calls per execution than baseline", severity: "medium", type: "trace", compliance: ["OWASP_LLM_TOP10", "MITRE_ATLAS"] },
  { id: "missing_trace_propagation", name: "Missing Trace Propagation", desc: "Workflow executions lack trace context", severity: "low", type: "trace", compliance: ["NIST_AI_RMF"] },
  { id: "unexpected_dependency", name: "Unexpected Dependency", desc: "Agent calling a service not in expected graph", severity: "high", type: "trace", compliance: ["MITRE_ATLAS", "OWASP_LLM_TOP10"] },
];
