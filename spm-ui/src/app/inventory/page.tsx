"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { getInventory } from "@/lib/api";

export default function InventoryPage() {
  const [items, setItems] = useState<any[]>([]);
  const [filter, setFilter] = useState("");
  const [search, setSearch] = useState("");

  const load = () => getInventory().then(d => setItems(d.items || [])).catch(console.error);
  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, []);

  const filtered = items.filter(i => {
    if (filter && i.source !== filter && i.agent_type !== filter) return false;
    if (search && !i.name?.toLowerCase().includes(search.toLowerCase()) && !i.agent_id?.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="max-w-6xl mx-auto px-8 py-8">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight"><span className="gradient-text">Agent Inventory</span></h1>
          <p className="text-gray-500 text-sm mt-1">{items.length} agents discovered across LiteLLM, Temporal & X-Ray</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 mb-6">
        <div className="relative flex-1">
          <span className="absolute left-4 top-3 text-gray-600 text-sm">⌕</span>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search agents..."
            className="w-full bg-white/[0.03] border border-white/10 rounded-xl pl-10 pr-4 py-2.5 text-sm focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/20 transition placeholder:text-gray-600" />
        </div>
        <div className="flex gap-1">
          {["", "litellm", "temporal", "model", "agent", "orchestrator"].map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`px-3 py-2 rounded-xl text-[11px] font-medium transition ${
                filter === f ? "bg-red-500/10 text-red-300 border border-red-500/20" : "bg-white/[0.03] text-gray-500 border border-white/[0.06] hover:bg-white/[0.06]"
              }`}>
              {f || "All"}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/5">
              <th className="text-left p-4 text-[10px] text-gray-500 uppercase tracking-widest font-medium">Agent</th>
              <th className="text-left p-4 text-[10px] text-gray-500 uppercase tracking-widest font-medium">Source</th>
              <th className="text-left p-4 text-[10px] text-gray-500 uppercase tracking-widest font-medium">Type</th>
              <th className="text-left p-4 text-[10px] text-gray-500 uppercase tracking-widest font-medium">Dependencies</th>
              <th className="text-left p-4 text-[10px] text-gray-500 uppercase tracking-widest font-medium">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(i => (
              <tr key={i.agent_id} className="border-b border-white/[0.03] hover:bg-white/[0.02] transition">
                <td className="p-4">
                  <Link href={`/inventory?id=${encodeURIComponent(i.agent_id)}`} className="text-red-400 hover:text-red-300 transition font-medium">
                    {i.name || i.agent_id}
                  </Link>
                </td>
                <td className="p-4"><SourceBadge source={i.source} /></td>
                <td className="p-4"><span className="text-gray-400 capitalize">{i.agent_type}</span></td>
                <td className="p-4">
                  {(i.dependencies || []).length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {i.dependencies.slice(0, 3).map((d: string) => (
                        <span key={d} className="bg-white/5 border border-white/[0.06] text-[10px] px-2 py-0.5 rounded-lg text-gray-500">{d}</span>
                      ))}
                      {i.dependencies.length > 3 && <span className="text-[10px] text-gray-600">+{i.dependencies.length - 3}</span>}
                    </div>
                  ) : <span className="text-gray-700 text-xs">—</span>}
                </td>
                <td className="p-4 text-[11px] text-gray-600 font-mono">{i.last_seen?.slice(0, 16).replace("T", " ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="border-t border-dashed border-white/10 p-16 text-center">
            <p className="text-gray-400 font-medium">{search || filter ? "No agents match" : "No agents discovered"}</p>
            <p className="text-gray-600 text-sm mt-1">Run a scan from the dashboard</p>
          </div>
        )}
      </div>
    </div>
  );
}

function SourceBadge({ source }: { source: string }) {
  const styles: Record<string, string> = {
    litellm: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    temporal: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    xray: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  };
  return <span className={`text-[10px] px-2.5 py-1 rounded-full font-medium border ${styles[source] || "bg-gray-500/10 text-gray-400 border-gray-500/20"}`}>{source}</span>;
}
