"use client";
import { useEffect, useState, useRef, useCallback } from "react";
import { getTopology, getInventory } from "@/lib/api";

// Example multi-agent topology shown in the "Agents" tab. This is illustrative
// sample data; the "X-Ray" tab renders the live service graph discovered from
// AWS X-Ray. Replace or remove this sample to match your own agents.
const AGENT_GRAPH = {
  nodes: [
    { id: "Orchestrator", type: "orchestrator", group: 0 },
    { id: "Agent A", type: "agent", group: 1 },
    { id: "Agent B", type: "agent", group: 1 },
    { id: "Agent C", type: "agent", group: 2 },
    { id: "Agent D", type: "agent", group: 2 },
    { id: "Agent E", type: "agent", group: 3 },
    { id: "Agent F", type: "agent", group: 4 },
    { id: "LiteLLM", type: "gateway", group: 5 },
    { id: "Bedrock", type: "llm", group: 5 },
    { id: "External API 1", type: "external", group: 6 },
    { id: "External API 2", type: "external", group: 6 },
  ],
  edges: [
    { source: "Orchestrator", target: "Agent A", label: "Phase 1", phase: 1 },
    { source: "Orchestrator", target: "Agent B", label: "Phase 1", phase: 1 },
    { source: "Agent A", target: "Agent C", label: "handoff", phase: 2 },
    { source: "Agent A", target: "Agent D", label: "handoff", phase: 2 },
    { source: "Agent B", target: "Agent E", label: "handoff", phase: 3 },
    { source: "Agent E", target: "Agent D", label: "handoff", phase: 4 },
    { source: "Agent B", target: "Agent F", label: "handoff", phase: 4 },
    { source: "Agent A", target: "LiteLLM", label: "", phase: 0 },
    { source: "Agent E", target: "LiteLLM", label: "", phase: 0 },
    { source: "Agent B", target: "LiteLLM", label: "", phase: 0 },
    { source: "Agent D", target: "LiteLLM", label: "", phase: 0 },
    { source: "Agent C", target: "LiteLLM", label: "", phase: 0 },
    { source: "Agent F", target: "LiteLLM", label: "", phase: 0 },
    { source: "LiteLLM", target: "Bedrock", label: "", phase: 0 },
    { source: "Agent A", target: "External API 1", label: "", phase: 0 },
    { source: "Agent A", target: "External API 2", label: "", phase: 0 },
    { source: "Agent E", target: "External API 1", label: "", phase: 0 },
    { source: "Agent F", target: "External API 1", label: "", phase: 0 },
    { source: "Agent F", target: "External API 2", label: "", phase: 0 },
  ],
};

const NODE_COLORS: Record<string, string> = {
  orchestrator: "#6366f1", agent: "#3b82f6", gateway: "#f59e0b",
  llm: "#10b981", external: "#8b5cf6",
};

const PHASE_COLORS = ["#4b5563", "#ef4444", "#f59e0b", "#3b82f6", "#10b981"];

interface SimNode {
  id: string; type: string; group: number;
  x: number; y: number; vx: number; vy: number;
}

export default function TopologyPage() {
  const [xrayTopo, setXrayTopo] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });
  const [tab, setTab] = useState<"agents" | "xray">("agents");
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const simRef = useRef<{ nodes: SimNode[]; settled: boolean }>({ nodes: [], settled: false });
  const hoveredRef = useRef<string | null>(null);
  const [hoveredInfo, setHoveredInfo] = useState<string | null>(null);
  const animRef = useRef<number>(0);

  useEffect(() => {
    getTopology().then(setXrayTopo).catch(console.error);
    const interval = setInterval(() => getTopology().then(setXrayTopo), 30000);
    return () => clearInterval(interval);
  }, []);

  const currentGraph = tab === "agents" ? AGENT_GRAPH : {
    nodes: [...new Map(xrayTopo.nodes.map(n => [n.name, { id: n.name, type: n.type?.includes("Lambda") ? "external" : n.type?.includes("Fargate") ? "agent" : "gateway", group: 0 }])).values()],
    edges: xrayTopo.edges.map(e => ({ source: e.source, target: e.target, label: `${e.avg_latency_ms?.toFixed(0)}ms`, phase: 0 })),
  };

  // Initialize simulation nodes only when graph changes
  useEffect(() => {
    const w = 500, h = 350;
    const existing = new Map(simRef.current.nodes.map(n => [n.id, n]));
    simRef.current.nodes = currentGraph.nodes.map((n, i) => {
      const prev = existing.get(n.id);
      if (prev) return { ...prev, type: n.type, group: n.group };
      // Layout in a circle initially
      const angle = (i / currentGraph.nodes.length) * Math.PI * 2;
      const r = 120 + n.group * 30;
      return { id: n.id, type: n.type, group: n.group, x: w / 2 + Math.cos(angle) * r, y: h / 2 + Math.sin(angle) * r, vx: 0, vy: 0 };
    });
    simRef.current.settled = false;
  }, [tab, xrayTopo]);

  // Animation loop — runs once, doesn't re-create on hover
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d")!;

    function tick() {
      const dpr = 2;
      const w = canvas!.offsetWidth;
      const h = canvas!.offsetHeight;
      canvas!.width = w * dpr;
      canvas!.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      const nodes = simRef.current.nodes;
      const edges = currentGraph.edges;
      const nodeMap = new Map(nodes.map(n => [n.id, n]));

      // Physics (only if not settled)
      if (!simRef.current.settled) {
        let totalV = 0;
        for (const n of nodes) {
          n.vx += (w / 2 - n.x) * 0.002;
          n.vy += (h / 2 - n.y) * 0.002;
          for (const m of nodes) {
            if (n === m) continue;
            const dx = n.x - m.x, dy = n.y - m.y;
            const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
            const force = 2000 / (dist * dist);
            n.vx += (dx / dist) * force;
            n.vy += (dy / dist) * force;
          }
        }
        for (const e of edges) {
          const s = nodeMap.get(e.source), t = nodeMap.get(e.target);
          if (!s || !t) continue;
          const dx = t.x - s.x, dy = t.y - s.y;
          const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
          const force = (dist - 100) * 0.003;
          s.vx += (dx / dist) * force; s.vy += (dy / dist) * force;
          t.vx -= (dx / dist) * force; t.vy -= (dy / dist) * force;
        }
        for (const n of nodes) {
          n.vx *= 0.8; n.vy *= 0.8;
          n.x += n.vx; n.y += n.vy;
          n.x = Math.max(50, Math.min(w - 50, n.x));
          n.y = Math.max(40, Math.min(h - 40, n.y));
          totalV += Math.abs(n.vx) + Math.abs(n.vy);
        }
        if (totalV < 0.5) simRef.current.settled = true;
      }

      // Draw
      ctx.clearRect(0, 0, w, h);
      const hovered = hoveredRef.current;

      // Edges
      for (const e of edges) {
        const s = nodeMap.get(e.source), t = nodeMap.get(e.target);
        if (!s || !t) continue;
        const isHighlighted = hovered === s.id || hovered === t.id;
        ctx.beginPath();
        ctx.moveTo(s.x, s.y); ctx.lineTo(t.x, t.y);
        ctx.strokeStyle = isHighlighted ? PHASE_COLORS[e.phase] || "#9ca3af" : e.phase > 0 ? PHASE_COLORS[e.phase] + "60" : "rgba(75,85,99,0.25)";
        ctx.lineWidth = isHighlighted ? 2.5 : e.phase > 0 ? 1.5 : 1;
        ctx.stroke();
        // Arrow
        const angle = Math.atan2(t.y - s.y, t.x - s.x);
        const mx = (s.x * 0.4 + t.x * 0.6), my = (s.y * 0.4 + t.y * 0.6);
        ctx.beginPath();
        ctx.moveTo(mx + 6 * Math.cos(angle), my + 6 * Math.sin(angle));
        ctx.lineTo(mx - 4 * Math.cos(angle - 0.5), my - 4 * Math.sin(angle - 0.5));
        ctx.lineTo(mx - 4 * Math.cos(angle + 0.5), my - 4 * Math.sin(angle + 0.5));
        ctx.closePath();
        ctx.fillStyle = isHighlighted ? PHASE_COLORS[e.phase] || "#9ca3af" : "rgba(107,114,128,0.3)";
        ctx.fill();
        // Label
        if (e.label && (isHighlighted || e.phase > 0)) {
          ctx.fillStyle = isHighlighted ? "#e5e7eb" : "rgba(156,163,175,0.6)";
          ctx.font = "9px sans-serif";
          ctx.textAlign = "center";
          ctx.fillText(e.label, (s.x + t.x) / 2, (s.y + t.y) / 2 - 6);
        }
      }

      // Nodes
      for (const n of nodes) {
        const color = NODE_COLORS[n.type] || "#6b7280";
        const isH = hovered === n.id;
        const r = isH ? 20 : 15;
        // Glow
        if (isH) {
          ctx.beginPath(); ctx.arc(n.x, n.y, r + 8, 0, Math.PI * 2);
          ctx.fillStyle = color + "20"; ctx.fill();
        }
        // Circle
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = color + "30"; ctx.strokeStyle = color; ctx.lineWidth = isH ? 2.5 : 1.5;
        ctx.fill(); ctx.stroke();
        // Icon
        ctx.fillStyle = "#e5e7eb"; ctx.font = `${isH ? 12 : 10}px sans-serif`; ctx.textAlign = "center"; ctx.textBaseline = "middle";
        const icons: Record<string, string> = { orchestrator: "⚡", agent: "⚙", gateway: "🔀", llm: "🧠", external: "🌐" };
        ctx.fillText(icons[n.type] || "◈", n.x, n.y);
        // Label
        ctx.fillStyle = isH ? "#f3f4f6" : "#9ca3af"; ctx.font = `${isH ? 11 : 10}px sans-serif`; ctx.textBaseline = "top";
        ctx.fillText(n.id, n.x, n.y + r + 4);
      }

      animRef.current = requestAnimationFrame(tick);
    }

    animRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animRef.current);
  }, [tab, xrayTopo]);

  // Mouse handler — updates ref, not state (no re-render)
  const handleMouse = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    let found: string | null = null;
    for (const n of simRef.current.nodes) {
      if (Math.sqrt((n.x - mx) ** 2 + (n.y - my) ** 2) < 20) { found = n.id; break; }
    }
    hoveredRef.current = found;
    setHoveredInfo(found);
  }, []);

  const avgLatency = xrayTopo.edges.length ? (xrayTopo.edges.reduce((s, e) => s + (e.avg_latency_ms || 0), 0) / xrayTopo.edges.length).toFixed(1) : "0";

  return (
    <div className="max-w-6xl mx-auto px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight"><span className="gradient-text">Service Topology</span></h1>
        <p className="text-gray-500 text-sm mt-1">Interactive agent dependency graph</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-4">
          <p className="text-[11px] text-gray-500 uppercase tracking-wider">Agents</p>
          <p className="text-2xl font-bold mt-1">{AGENT_GRAPH.nodes.filter(n => n.type === "agent").length}</p>
        </div>
        <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-4">
          <p className="text-[11px] text-gray-500 uppercase tracking-wider">X-Ray Nodes</p>
          <p className="text-2xl font-bold mt-1">{new Set(xrayTopo.nodes.map(n => n.name)).size}</p>
        </div>
        <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-4">
          <p className="text-[11px] text-gray-500 uppercase tracking-wider">Avg Latency</p>
          <p className="text-2xl font-bold mt-1">{avgLatency}<span className="text-sm text-gray-500 ml-1">ms</span></p>
        </div>
        <div className="bg-white/[0.03] border border-white/[0.06] rounded-xl p-4">
          <p className="text-[11px] text-gray-500 uppercase tracking-wider">Collaboration Phases</p>
          <p className="text-2xl font-bold mt-1">4</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4">
        <button onClick={() => setTab("agents")}
          className={`px-4 py-2.5 rounded-xl text-[13px] font-medium transition ${tab === "agents" ? "bg-red-500/10 text-red-300 border border-red-500/20" : "bg-white/[0.03] text-gray-500 border border-white/[0.06]"}`}>
          ⚙ Agent Collaboration
        </button>
        <button onClick={() => setTab("xray")}
          className={`px-4 py-2.5 rounded-xl text-[13px] font-medium transition ${tab === "xray" ? "bg-red-500/10 text-red-300 border border-red-500/20" : "bg-white/[0.03] text-gray-500 border border-white/[0.06]"}`}>
          ◎ X-Ray Service Map
        </button>
      </div>

      {/* Graph */}
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-2 mb-6">
        <canvas ref={canvasRef} onMouseMove={handleMouse} onMouseLeave={() => { hoveredRef.current = null; setHoveredInfo(null); }}
          className="w-full rounded-xl cursor-crosshair" style={{ height: 420 }} />
        <div className="flex items-center justify-between px-4 py-3">
          <div className="flex gap-4">
            {Object.entries(NODE_COLORS).map(([type, color]) => (
              <span key={type} className="flex items-center gap-1.5 text-[10px] text-gray-500">
                <span className="w-3 h-3 rounded-full" style={{ backgroundColor: color + "80" }} />{type}
              </span>
            ))}
          </div>
          {hoveredInfo && <span className="text-[11px] text-gray-400">Hovering: <span className="text-white font-medium">{hoveredInfo}</span></span>}
          {tab === "agents" && (
            <div className="flex gap-3">
              {[1, 2, 3, 4].map(p => (
                <span key={p} className="flex items-center gap-1 text-[10px] text-gray-500">
                  <span className="w-3 h-0.5 rounded" style={{ backgroundColor: PHASE_COLORS[p] }} />Phase {p}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Edge table */}
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl overflow-hidden">
        <div className="p-6 pb-3"><p className="text-[10px] text-gray-500 uppercase tracking-widest">{tab === "agents" ? "Agent Communication Flow" : "X-Ray Connections"}</p></div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/5">
              <th className="text-left p-4 pt-0 text-[10px] text-gray-500 uppercase tracking-widest font-medium">Source</th>
              <th className="text-left p-4 pt-0 text-[10px] text-gray-500 uppercase tracking-widest font-medium w-8"></th>
              <th className="text-left p-4 pt-0 text-[10px] text-gray-500 uppercase tracking-widest font-medium">Target</th>
              <th className="text-left p-4 pt-0 text-[10px] text-gray-500 uppercase tracking-widest font-medium">{tab === "agents" ? "Data Flow" : "Latency"}</th>
              {tab === "agents" && <th className="text-left p-4 pt-0 text-[10px] text-gray-500 uppercase tracking-widest font-medium">Phase</th>}
              {tab === "xray" && <th className="text-right p-4 pt-0 text-[10px] text-gray-500 uppercase tracking-widest font-medium">Requests</th>}
            </tr>
          </thead>
          <tbody>
            {(tab === "agents" ? AGENT_GRAPH.edges.filter(e => e.phase > 0) : xrayTopo.edges).map((e, i) => (
              <tr key={i} className="border-b border-white/[0.03] hover:bg-white/[0.02] transition">
                <td className="p-4 font-medium">{e.source}</td>
                <td className="p-4 text-gray-600">→</td>
                <td className="p-4 font-medium">{e.target}</td>
                <td className="p-4 text-gray-400">{e.label || (tab === "xray" ? `${(e as any).avg_latency_ms?.toFixed(1)}ms` : "")}</td>
                {tab === "agents" && <td className="p-4"><span className="text-[10px] px-2 py-0.5 rounded-full font-medium" style={{ backgroundColor: PHASE_COLORS[(e as any).phase] + "20", color: PHASE_COLORS[(e as any).phase] }}>Phase {(e as any).phase}</span></td>}
                {tab === "xray" && <td className="p-4 text-right font-mono text-gray-400">{((e as any).request_count || 0).toLocaleString()}</td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
