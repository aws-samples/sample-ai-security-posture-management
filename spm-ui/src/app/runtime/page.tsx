"use client";
import { useEffect, useState, useCallback } from "react";
import { getRuntimeEvents, getRuntimeAlerts, getRuntimeStats } from "@/lib/api";

const SEVERITY_OPTIONS = ["", "critical", "high", "medium", "low"];

export default function RuntimePage() {
  const [allEvents, setAllEvents] = useState<any[]>([]);
  const [allAlerts, setAllAlerts] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [tab, setTab] = useState<"alerts" | "events">("alerts");
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);

  const PER_PAGE = 10;

  // Load all events (fetch multiple pages from API to get full dataset)
  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      // Load events in batches until we have enough or no more
      let events: any[] = [];
      let cursor: string | undefined;
      for (let i = 0; i < 5; i++) { // max 5 API pages = 250 events
        const d = await getRuntimeEvents(50, cursor);
        events = [...events, ...(d.events || [])];
        if (!d.has_more || !d.next_cursor) break;
        cursor = d.next_cursor;
      }
      setAllEvents(events);
      const a = await getRuntimeAlerts();
      setAllAlerts(a.alerts || []);
      getRuntimeStats().then(setStats);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadAll();
    const interval = setInterval(loadAll, 15000);
    return () => clearInterval(interval);
  }, [loadAll]);

  // Filter
  const filterFn = (e: any) => {
    if (sevFilter && e.severity !== sevFilter) return false;
    if (typeFilter && e.event_type !== typeFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      const haystack = `${e.event_type} ${e.agent_id} ${e.severity} ${JSON.stringify(e.details || {})}`.toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  };

  const filtered = (tab === "alerts" ? allAlerts : allEvents).filter(filterFn);
  const totalPages = Math.ceil(filtered.length / PER_PAGE) || 1;
  const safePage = Math.min(page, totalPages);
  const paged = filtered.slice((safePage - 1) * PER_PAGE, safePage * PER_PAGE);

  // Reset page on filter/tab change
  useEffect(() => { setPage(1); }, [search, sevFilter, typeFilter, tab]);

  const eventTypes = [...new Set([...allEvents, ...allAlerts].map(e => e.event_type))].filter(Boolean).sort();

  return (
    <div className="max-w-6xl mx-auto px-8 py-8">
      <div className="flex items-end justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight"><span className="gradient-text">Runtime Monitoring</span></h1>
          <p className="text-gray-500 text-sm mt-1">Live detection & response — auto-refreshes every 15s</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-[11px] text-gray-500">Live</span>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-4 gap-3 mb-8">
          <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-4">
            <p className="text-[11px] text-gray-500 uppercase tracking-wider">Total Events</p>
            <p className="text-2xl font-bold mt-1">{stats.total}</p>
          </div>
          <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-4">
            <p className="text-[11px] text-gray-500 uppercase tracking-wider">Critical</p>
            <p className="text-2xl font-bold mt-1 text-red-400">{stats.by_severity?.critical || 0}</p>
          </div>
          <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-4">
            <p className="text-[11px] text-gray-500 uppercase tracking-wider">By Type</p>
            <div className="mt-1 space-y-0.5">
              {Object.entries(stats.by_type || {}).map(([k, v]) => (
                <div key={k} className="flex justify-between text-[11px]"><span className="text-gray-500">{k}</span><span className="font-mono">{v as number}</span></div>
              ))}
            </div>
          </div>
          <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-4">
            <p className="text-[11px] text-gray-500 uppercase tracking-wider">Top Agents</p>
            <div className="mt-1 space-y-0.5">
              {Object.entries(stats.by_agent || {}).slice(0, 4).map(([k, v]) => (
                <div key={k} className="flex justify-between text-[11px]"><span className="text-gray-500 truncate max-w-[120px]">{k}</span><span className="font-mono">{v as number}</span></div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Search + Filters */}
      <div className="flex items-center gap-3 mb-4">
        <div className="relative flex-1">
          <span className="absolute left-4 top-3 text-gray-600 text-sm">⌕</span>
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search by type, agent, pattern, details..."
            className="w-full bg-white/[0.03] border border-white/10 rounded-xl pl-10 pr-4 py-2.5 text-sm focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/20 transition placeholder:text-gray-600" />
        </div>
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
          className="bg-white/[0.03] border border-white/10 rounded-xl px-3 py-2.5 text-sm text-gray-300 focus:outline-none focus:border-red-500/50">
          <option value="">All Severities</option>
          {SEVERITY_OPTIONS.filter(Boolean).map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
          className="bg-white/[0.03] border border-white/10 rounded-xl px-3 py-2.5 text-sm text-gray-300 focus:outline-none focus:border-red-500/50">
          <option value="">All Types</option>
          {eventTypes.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        {(search || sevFilter || typeFilter) && (
          <button onClick={() => { setSearch(""); setSevFilter(""); setTypeFilter(""); }}
            className="text-[11px] text-gray-500 hover:text-red-400 transition whitespace-nowrap">Clear ✕</button>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4">
        <button onClick={() => setTab("alerts")}
          className={`px-4 py-2.5 rounded-xl text-[13px] font-medium transition ${
            tab === "alerts" ? "bg-red-500/10 text-red-300 border border-red-500/20" : "bg-white/[0.03] text-gray-500 border border-white/[0.06]"
          }`}>
          ◉ Alerts ({(tab === "alerts" ? filtered : allAlerts.filter(filterFn)).length})
        </button>
        <button onClick={() => setTab("events")}
          className={`px-4 py-2.5 rounded-xl text-[13px] font-medium transition ${
            tab === "events" ? "bg-red-500/10 text-red-300 border border-red-500/20" : "bg-white/[0.03] text-gray-500 border border-white/[0.06]"
          }`}>
          ◈ All Events ({(tab === "events" ? filtered : allEvents.filter(filterFn)).length})
        </button>
      </div>

      {/* Event list */}
      <div className="space-y-2">
        {paged.map(e => (
          <div key={e.event_id} className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-4 hover:border-white/10 transition">
            <div className="flex items-start gap-3">
              <SevDot severity={e.severity} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-sm">{e.event_type}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium border ${
                      e.severity === "critical" ? "bg-red-500/10 text-red-400 border-red-500/20" :
                      e.severity === "high" ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                      e.severity === "medium" ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" :
                      "bg-blue-500/10 text-blue-400 border-blue-500/20"
                    }`}>{e.severity}</span>
                  </div>
                  <span className="text-[11px] text-gray-600 font-mono">{e.timestamp?.slice(0, 19).replace("T", " ")}</span>
                </div>
                <p className="text-[11px] text-gray-500 mt-1">Agent: <span className="text-gray-400 font-mono">{e.agent_id}</span></p>
                {e.trace_id && <p className="text-[11px] text-blue-400/70 mt-0.5 font-mono">Trace: {e.trace_id}</p>}
                {e.details && (
                  <div className="mt-2 bg-white/[0.02] border border-white/[0.04] rounded-xl p-3">
                    <pre className="text-[11px] text-gray-500 overflow-x-auto whitespace-pre-wrap">{JSON.stringify(e.details, null, 2)}</pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}

        {paged.length === 0 && (
          <div className="border border-dashed border-white/10 rounded-2xl p-16 text-center">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-red-500/20 to-orange-500/20 flex items-center justify-center mx-auto mb-4"><span className="text-2xl">✦</span></div>
            <p className="text-gray-400 font-medium">{search || sevFilter || typeFilter ? "No matches" : `No ${tab} yet`}</p>
          </div>
        )}
      </div>

      {/* Numbered Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-1 mt-6">
          <button onClick={() => setPage(Math.max(1, safePage - 1))} disabled={safePage <= 1}
            className="px-3 py-1.5 rounded-lg bg-white/5 text-xs disabled:opacity-20 hover:bg-white/10 transition">←</button>
          {pageNumbers(safePage, totalPages).map((p, i) =>
            p === "..." ? <span key={`dot-${i}`} className="px-2 text-gray-600 text-xs">...</span> : (
              <button key={p} onClick={() => setPage(p as number)}
                className={`w-8 h-8 rounded-lg text-xs font-medium transition ${
                  p === safePage ? "bg-red-500/20 text-red-300 border border-red-500/30" : "bg-white/5 text-gray-400 hover:bg-white/10"
                }`}>{p}</button>
            )
          )}
          <button onClick={() => setPage(Math.min(totalPages, safePage + 1))} disabled={safePage >= totalPages}
            className="px-3 py-1.5 rounded-lg bg-white/5 text-xs disabled:opacity-20 hover:bg-white/10 transition">→</button>
          <span className="text-[11px] text-gray-600 ml-3">{filtered.length} results</span>
        </div>
      )}
    </div>
  );
}

/** Generate page numbers with ellipsis: 1 2 3 ... 8 9 10 */
function pageNumbers(current: number, total: number): (number | string)[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const pages: (number | string)[] = [];
  if (current <= 4) {
    for (let i = 1; i <= 5; i++) pages.push(i);
    pages.push("...", total);
  } else if (current >= total - 3) {
    pages.push(1, "...");
    for (let i = total - 4; i <= total; i++) pages.push(i);
  } else {
    pages.push(1, "...", current - 1, current, current + 1, "...", total);
  }
  return pages;
}

function SevDot({ severity }: { severity: string }) {
  const c: Record<string, string> = { critical: "bg-red-500", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-blue-500" };
  return <span className={`w-3 h-3 rounded-full mt-0.5 flex-shrink-0 ${c[severity] || "bg-gray-500"}`} />;
}
