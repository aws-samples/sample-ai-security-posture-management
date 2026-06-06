"use client";
import { useEffect, useState } from "react";
import { getDefenderConfig, setDefenderMode } from "@/lib/api";

export default function SettingsPage() {
  const [config, setConfig] = useState<any>({ mode: "monitor", rules: {}, bypass_keys: [] });
  const [saving, setSaving] = useState(false);

  useEffect(() => { getDefenderConfig().then(setConfig).catch(console.error); }, []);

  async function toggleMode() {
    setSaving(true);
    const newMode = config.mode === "monitor" ? "enforce" : "monitor";
    try { await setDefenderMode(newMode); setConfig({ ...config, mode: newMode }); }
    finally { setSaving(false); }
  }

  const isEnforce = config.mode === "enforce";

  return (
    <div className="max-w-4xl mx-auto px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight"><span className="gradient-text">Defender Settings</span></h1>
        <p className="text-gray-500 text-sm mt-1">Configure runtime enforcement and detection rules</p>
      </div>

      {/* Mode Toggle */}
      <div className={`bg-gradient-to-br ${isEnforce ? "from-red-500/20 to-rose-500/20 border-red-500/10" : "from-amber-500/20 to-yellow-500/20 border-amber-500/10"} border rounded-2xl p-6 mb-6`}>
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2.5 mb-2">
              <span className="text-xl">{isEnforce ? "🛡" : "👁"}</span>
              <p className="font-semibold text-[15px]">Enforcement Mode</p>
            </div>
            <p className="text-sm text-gray-400">
              {isEnforce
                ? "Active enforcement — threats are blocked before reaching the LLM"
                : "Monitor only — threats are detected and logged but not blocked"}
            </p>
          </div>
          <button onClick={toggleMode} disabled={saving}
            className={`px-6 py-3 rounded-xl text-sm font-medium transition shadow-lg ${
              isEnforce
                ? "bg-red-600 hover:bg-red-500 shadow-red-500/20"
                : "bg-amber-600 hover:bg-amber-500 shadow-amber-500/20"
            } disabled:opacity-50`}>
            {saving ? "Switching..." : isEnforce ? "⚡ ENFORCE" : "👁 MONITOR"}
          </button>
        </div>
      </div>

      {/* Detection Rules */}
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-6 mb-6">
        <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-4">Detection Rules</p>
        <div className="space-y-1">
          {[
            { name: "Prompt Injection Detection", desc: "Block requests matching known injection patterns (9 signatures)", active: true, severity: "critical" },
            { name: "Rate Limiting", desc: "Block keys exceeding 60 requests/minute", active: true, severity: "high" },
            { name: "Budget Enforcement", desc: "Block keys that have exceeded their spend budget", active: true, severity: "high" },
            { name: "Model Allowlist", desc: "Block requests to models not in the key's allowlist", active: true, severity: "medium" },
            { name: "Anomalous Trace Patterns", desc: "Block agents with unexpected execution paths from X-Ray analysis", active: false, severity: "high" },
          ].map(r => (
            <div key={r.name} className="flex items-center justify-between py-3 border-b border-white/5 last:border-0">
              <div className="flex items-center gap-3">
                <span className={`w-2 h-2 rounded-full ${r.active ? "bg-emerald-500" : "bg-gray-600"}`} />
                <div>
                  <p className="text-sm font-medium">{r.name}</p>
                  <p className="text-[11px] text-gray-600">{r.desc}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-[10px] px-2 py-0.5 rounded-full border ${
                  r.severity === "critical" ? "bg-red-500/10 text-red-400 border-red-500/20" :
                  r.severity === "high" ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                  "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
                }`}>{r.severity}</span>
                <span className={`text-[10px] px-2.5 py-1 rounded-full font-medium border ${
                  r.active ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-gray-500/10 text-gray-500 border-gray-500/20"
                }`}>{r.active ? "Active" : "Inactive"}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Bypass Keys */}
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-6">
        <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-2">Bypass Keys</p>
        <p className="text-[11px] text-gray-600 mb-4">Keys exempted from enforcement (still monitored and logged)</p>
        {(config.bypass_keys || []).length === 0
          ? <p className="text-sm text-gray-600">No bypass keys configured</p>
          : (config.bypass_keys || []).map((k: string) => (
            <span key={k} className="inline-block bg-white/5 border border-white/[0.06] text-[11px] px-3 py-1.5 rounded-lg mr-2 font-mono">{k}</span>
          ))
        }
      </div>
    </div>
  );
}
