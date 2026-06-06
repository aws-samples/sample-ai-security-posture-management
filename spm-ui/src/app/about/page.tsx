"use client";

export default function AboutPage() {
  return (
    <div className="max-w-5xl mx-auto px-8 py-8 space-y-10">
      <div>
        <h1 className="text-3xl font-bold tracking-tight"><span className="gradient-text">About AI SPM</span></h1>
        <p className="text-gray-500 mt-2 max-w-2xl">
          AI Security Posture Management for AI agent platforms. Discovers, assesses, and protects AI agents
          running in LiteLLM and Temporal — powered by X-Ray trace analysis, policy evaluation, and real-time
          prompt injection detection. Built entirely on AWS native services.
        </p>
      </div>

      {/* Featured Use Case — Hospitality */}
      <div className="bg-gradient-to-br from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-2xl p-6">
        <div className="flex items-center gap-2 mb-2">
          <span className="text-xl">🏨</span>
          <span className="text-[10px] text-red-400 uppercase tracking-widest">Featured Use Case · Hospitality</span>
        </div>
        <h2 className="text-xl font-semibold mb-2">Group Sales &amp; Event Management with AI Planning</h2>
        <p className="text-sm text-gray-400 leading-relaxed max-w-3xl">
          Hotels and venues run group sales and events with multi-agent AI — qualifying RFPs, checking space and
          room availability, building menus, drafting banquet event orders, pricing packages, and generating
          proposals across PMS, CRM, catering, and payment systems. These agents are autonomous, highly privileged
          (guest PII, negotiated pricing, payments), and ingest untrusted inbound content (RFP emails and documents).
          AI SPM observes the agents, governs their posture, and defends against injected RFPs, data exfiltration,
          over-privileged keys, and unexpected dependencies.
        </p>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2 mt-4">
          {[
            "Group Sales Inquiry", "RFP Response", "Venue Allocation",
            "Catering & Banquet", "Room Block", "Banquet Event Order",
            "Scheduling", "Pricing & Contracting", "Vendor Coordination",
          ].map((a) => (
            <div key={a} className="bg-white/[0.03] border border-white/[0.06] rounded-lg px-3 py-2 text-xs text-gray-300 text-center">{a}</div>
          ))}
        </div>
        <p className="text-[11px] text-gray-500 mt-4">
          Ready-to-run baseline: <span className="font-mono text-gray-400">config/hospitality-group-sales.example.json</span>
        </p>
      </div>
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-6">
        <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-4">System Architecture</p>
        <img src="/architecture.png" alt="AI SPM Architecture" className="w-full rounded-xl" />
      </div>

      {/* How It Works */}
      <div>
        <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-4">How It Works</p>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[
            { step: "01", title: "Discover", desc: "Scanners poll LiteLLM (models, keys, spend), Temporal (workflows, activities), and X-Ray (traces, topology) every 5 minutes.", icon: "🔍" },
            { step: "02", title: "Assess", desc: "10 policy rules evaluate agent configs and trace-derived behavior against OWASP, NIST, and MITRE compliance frameworks.", icon: "📋" },
            { step: "03", title: "Detect", desc: "Runtime monitoring intercepts LLM calls for prompt injection (9 patterns), rate limiting, and anomalous execution paths from X-Ray.", icon: "🛡" },
            { step: "04", title: "Respond", desc: "In enforce mode, threats are blocked before reaching Bedrock. In monitor mode, everything is logged for investigation.", icon: "⚡" },
          ].map((s) => (
            <div key={s.step} className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-5">
              <div className="flex items-center gap-3 mb-3">
                <span className="text-2xl">{s.icon}</span>
                <span className="text-[10px] text-red-400 font-mono">{s.step}</span>
              </div>
              <h3 className="font-semibold text-[15px] mb-1">{s.title}</h3>
              <p className="text-xs text-gray-500 leading-relaxed">{s.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Three Pillars */}
      <div>
        <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-4">The Three Pillars</p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            {
              name: "Observe", icon: "🔍", color: "from-blue-500/20 to-cyan-500/20 border-blue-500/10",
              desc: "Continuous discovery and inventory of all AI agents across LiteLLM and Temporal, enriched with X-Ray behavioral baselines and service topology mapping.",
              features: ["Auto-discovery from LiteLLM, Temporal, X-Ray", "Agent inventory with dependency graphs", "Service topology visualization", "Behavioral baseline computation", "Delta detection (new/changed/removed)"],
            },
            {
              name: "Govern", icon: "📋", color: "from-amber-500/20 to-orange-500/20 border-amber-500/10",
              desc: "Policy engine evaluating agent configurations and trace-derived behavior against security rules mapped to industry compliance frameworks.",
              features: ["10 built-in security rules", "5 config-based + 5 trace-based rules", "OWASP LLM Top 10 mapping", "NIST AI RMF compliance", "MITRE ATLAS threat coverage", "Finding lifecycle (open → ack → resolve)"],
            },
            {
              name: "Defend", icon: "🛡", color: "from-red-500/20 to-rose-500/20 border-red-500/10",
              desc: "Real-time threat detection and configurable inline blocking. Intercepts LLM calls for prompt injection, analyzes X-Ray traces for behavioral anomalies.",
              features: ["9 prompt injection patterns", "Rate limiting per API key", "Monitor or enforce mode", "X-Ray trace anomaly detection", "Multi-signal alert correlation", "Severity escalation engine"],
            },
          ].map((p) => (
            <div key={p.name} className={`bg-gradient-to-br ${p.color} border rounded-2xl p-5`}>
              <div className="flex items-center gap-2.5 mb-3">
                <span className="text-2xl">{p.icon}</span>
                <h3 className="font-semibold text-[15px]">{p.name}</h3>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed mb-3">{p.desc}</p>
              <div className="space-y-1.5">
                {p.features.map((f) => (
                  <div key={f} className="flex items-center gap-2 text-[11px] text-gray-500">
                    <span className="text-emerald-500 text-[10px]">✓</span>{f}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Data Flow */}
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-6">
        <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-4">Data Flow</p>
        <div className="space-y-2 text-sm font-mono">
          {[
            { source: "LiteLLM API", flow: "/model/info, /key/info, /spend/logs → Agent inventory (models, keys, budgets)", color: "text-blue-400" },
            { source: "Temporal SDK", flow: "list_workflows, describe_workflow → Workflow types, execution stats, failure rates", color: "text-purple-400" },
            { source: "X-Ray API", flow: "GetServiceGraph → Topology · GetTraceSummaries + BatchGetTraces → Behavioral baselines", color: "text-emerald-400" },
            { source: "LiteLLM Callback", flow: "async_pre_call_hook → Prompt injection scan → Block (enforce) or Log (monitor)", color: "text-red-400" },
            { source: "Trace Analyzer", flow: "Recent traces → Anomalous edges + Latency spikes → Correlated alerts", color: "text-amber-400" },
          ].map((d) => (
            <div key={d.source} className="flex items-start gap-4 py-1">
              <span className="text-[10px] text-gray-600 w-28 flex-shrink-0 pt-0.5">{d.source}</span>
              <span className={`text-xs ${d.color}`}>{d.flow}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Policy Rules */}
      <div>
        <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-4">Security Rules (16)</p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-5">
            <p className="text-[10px] text-blue-400 uppercase tracking-widest mb-3">Config-Based (5)</p>
            {[
              { rule: "overprivileged_key", sev: "HIGH", desc: "No budget limit or model restrictions" },
              { rule: "missing_guardrails", sev: "MED", desc: "No max_tokens configured" },
              { rule: "unrestricted_model_access", sev: "HIGH", desc: "No model allowlist" },
              { rule: "excessive_spend", sev: "MED", desc: "Spend >80% of budget" },
              { rule: "stale_agent", sev: "LOW", desc: "Zero executions" },
            ].map((r) => (
              <div key={r.rule} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                <div>
                  <p className="text-xs font-medium font-mono">{r.rule}</p>
                  <p className="text-[10px] text-gray-600">{r.desc}</p>
                </div>
                <span className={`text-[9px] px-2 py-0.5 rounded-full font-medium ${
                  r.sev === "HIGH" ? "bg-orange-500/10 text-orange-400" : r.sev === "MED" ? "bg-yellow-500/10 text-yellow-400" : "bg-blue-500/10 text-blue-400"
                }`}>{r.sev}</span>
              </div>
            ))}
          </div>
          <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-5">
            <p className="text-[10px] text-purple-400 uppercase tracking-widest mb-3">Trace-Based (5)</p>
            {[
              { rule: "unexpected_dependency", sev: "HIGH", desc: "New edge in service graph" },
              { rule: "high_retry_rate", sev: "HIGH", desc: ">10% failure rate" },
              { rule: "latency_anomaly", sev: "MED", desc: "P95 >3× average" },
              { rule: "excessive_llm_calls", sev: "MED", desc: ">5 LLM calls per execution" },
              { rule: "missing_trace_propagation", sev: "LOW", desc: "Executions without traces" },
            ].map((r) => (
              <div key={r.rule} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                <div>
                  <p className="text-xs font-medium font-mono">{r.rule}</p>
                  <p className="text-[10px] text-gray-600">{r.desc}</p>
                </div>
                <span className={`text-[9px] px-2 py-0.5 rounded-full font-medium ${
                  r.sev === "HIGH" ? "bg-orange-500/10 text-orange-400" : r.sev === "MED" ? "bg-yellow-500/10 text-yellow-400" : "bg-blue-500/10 text-blue-400"
                }`}>{r.sev}</span>
              </div>
            ))}
          </div>
          <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-5">
            <p className="text-[10px] text-red-400 uppercase tracking-widest mb-3">Agentic / Runtime (6)</p>
            {[
              { rule: "sensitive_data_exposure", sev: "CRIT", desc: "PII/secret exfiltration" },
              { rule: "jailbreak_activity", sev: "HIGH", desc: "Jailbreak attempts" },
              { rule: "insecure_output_handling", sev: "HIGH", desc: "Unsafe output (scripts/links)" },
              { rule: "excessive_agency", sev: "HIGH", desc: "Too many / wide tool use" },
              { rule: "unapproved_model", sev: "MED", desc: "Model outside allowlist" },
              { rule: "missing_guardrail_association", sev: "MED", desc: "No Bedrock guardrail" },
            ].map((r) => (
              <div key={r.rule} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                <div>
                  <p className="text-xs font-medium font-mono">{r.rule}</p>
                  <p className="text-[10px] text-gray-600">{r.desc}</p>
                </div>
                <span className={`text-[9px] px-2 py-0.5 rounded-full font-medium ${
                  r.sev === "CRIT" ? "bg-red-500/10 text-red-400" : r.sev === "HIGH" ? "bg-orange-500/10 text-orange-400" : "bg-yellow-500/10 text-yellow-400"
                }`}>{r.sev}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Tech Stack */}
      <div>
        <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-4">Technology Stack</p>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
          {[
            "Amazon Bedrock", "Claude (Bedrock)", "LiteLLM Gateway", "Temporal", "AWS X-Ray",
            "ECS Fargate", "CloudFront", "DynamoDB (×4)", "Amazon Cognito", "ADOT Collector",
            "OpenTelemetry", "CloudFormation", "VPC Endpoints", "Next.js 15", "FastAPI",
            "Python 3.12", "TypeScript", "Tailwind CSS", "boto3", "httpx",
          ].map((t) => (
            <div key={t} className="bg-white/[0.03] border border-white/[0.06] rounded-lg px-3 py-2 text-xs text-gray-400 text-center">{t}</div>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="bg-white/[0.02] border border-white/[0.06] rounded-2xl p-6">
        <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-4">By The Numbers</p>
        <div className="grid grid-cols-4 md:grid-cols-8 gap-3">
          {[
            { label: "Python Files", value: "17" }, { label: "Lines of Code", value: "1,884" },
            { label: "API Endpoints", value: "24" }, { label: "Policy Rules", value: "10" },
            { label: "UI Pages", value: "8" }, { label: "DynamoDB Tables", value: "4" },
            { label: "CFN Stacks", value: "2" }, { label: "Policy Rules", value: "16" },
          ].map((s) => (
            <div key={s.label} className="text-center">
              <p className="text-lg font-bold">{s.value}</p>
              <p className="text-[9px] text-gray-600">{s.label}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
