# AI SPM vs. commercial AI agent security platforms

An **honest** comparison between this open-source sample and the category of
commercial, enterprise AI agent security platforms (AISPM + AIDR). We do not
name specific vendors; the intent is a fair capability comparison, not a
competitive teardown.

> **TL;DR (read this first).** These are not the same kind of thing. Leading
> commercial products are mature, multi-platform, managed offerings. This
> project is an **open-source, AWS-native reference implementation and
> accelerator**. We do **not** beat commercial leaders on platform breadth,
> detection maturity, or enterprise operations — claiming otherwise would be
> dishonest. Where this project wins is **open source, in-account/self-hosted,
> transparent, extensible, and zero-lock-in** — a compelling choice for AWS
> teams (especially LiteLLM/Temporal/Bedrock workloads, and regulated/sovereign
> environments) who want to own and customize their AI-agent security posture
> without a SaaS overlay.

## What leading commercial platforms ship today

To compare fairly, mature commercial AI agent security platforms generally offer:

- **Three pillars**: observability, AI Security Posture Management (AISPM), and
  AI Detection & Response (AIDR).
- **Intent-based AIDR** — inferring an agent's *intent* from the full execution
  path (tool calls, memory access, data usage, control flow) with **build-time →
  runtime correlation** and automated response (quarantine, blocking, revocation).
- **Broad platform coverage** — SaaS agent platforms, multiple clouds (including
  Amazon Bedrock and Bedrock AgentCore), and endpoint/device environments.
- **Enterprise maturity** — analyst recognition, compliance attestations
  (e.g., FedRAMP), managed SLAs, dedicated threat research, and autonomous
  "guardian"-style response agents.

This project targets the **AWS-native, code-first agent** slice of that space
(LiteLLM + Temporal + Bedrock + AgentCore + X-Ray).

## Capability matrix

| Capability | Commercial leaders | AI SPM (this project) | Verdict |
|------------|--------------------|------------------------|---------|
| Observe / Govern / Defend model | ✅ | ✅ | Match |
| Discovery breadth | ✅ SaaS + multi-cloud + endpoint | ⚠️ AWS-native: LiteLLM, Temporal, Bedrock, **Bedrock AgentCore**, SageMaker, Lambda, shadow AI | **They lead** (breadth) |
| Posture rules + compliance mapping | ✅ | ✅ 26 rules → OWASP LLM 2025, OWASP Agentic ASI01–ASI10, NIST AI RMF, MITRE ATLAS, AWS SRA for AI | Match |
| Quantitative risk scoring | ✅ | ✅ 0–100 + posture score | Match |
| Prompt injection / jailbreak / extraction | ✅ | ✅ regex + Bedrock-semantic + optional OSS ensemble | Match |
| Data exfiltration / PII / insecure output | ✅ | ✅ (+ optional Presidio) | Match |
| **Intent-based detection** | ✅ deep (full execution-path intent inference) | ✅ `intent_alignment` detector (sanctioned-model/tool correlation, session intent drift, optional Bedrock intent classifier) | **They lead** (depth) |
| **Build-time → runtime correlation** | ✅ | ✅ runtime model/tools/tokens vs inventory config + baseline | **They lead** (depth); we now have it |
| Inline enforcement | ✅ multi-platform | ✅ transparent proxy + Bedrock Guardrails (AWS) | Match (AWS scope) |
| **Autonomous graduated response** | ✅ mature | ✅ Guardian orchestrator (off/recommend/auto; quarantine/revoke/block; audited) | Match (concept); they lead (maturity) |
| Bedrock AgentCore support | ✅ | ✅ AgentCore scanner (runtimes/gateways/memories) + 4 posture rules | Match (on AWS) |
| Agent identity / NHI (ASI03) | ✅ | ✅ execution-role privilege analysis | Match |
| AIDR / SecOps integration | ✅ SIEM/SOAR | ✅ **AWS-native**: Security Hub (ASFF), GuardDuty AI Protection ingest, SNS, EventBridge | Match (AWS-native edge) |
| Multi-agent / drift monitoring | ✅ | ⚠️ session drift + attack-chain correlation (lighter) | They lead |
| Endpoint / device coverage | ✅ | ❌ | They lead |
| Enterprise maturity (analyst/compliance/SLA/support) | ✅ | ❌ sample code | They lead |
| **Open source & self-hostable** | ❌ | ✅ Apache-2.0, runs in your account | **We lead** |
| **Extensible by design (plugins)** | ⚠️ vendor-defined | ✅ detector/rule/scanner/sink registries + `SPM_PLUGINS` | **We lead** |
| **Transparent, auditable detection** | ❌ proprietary | ✅ readable rules mapped to frameworks | **We lead** |
| **No vendor lock-in / OSS ensemble** | ❌ | ✅ optional OSS detectors | **We lead** |
| **Self-serve red-team benchmark** | ⚠️ research-led | ✅ `POST /spm/api/redteam/run` scores your real stack | **We lead** |
| **Cost / data residency / sovereignty** | $$ SaaS | Your account, your region, your data | **We lead** |

## Where this project genuinely differentiates

1. **Open source (Apache-2.0), 100% in-account.** No SaaS overlay; data never leaves
   the customer's account/region. Strong for regulated/sovereign/air-gapped use.
2. **Extensible by design.** Add detectors, rules, scanners, and integrations as
   drop-in plugins via `SPM_PLUGINS` — including for **other platforms** — with
   no core changes. See [extending.md](extending.md).
3. **Transparent detection.** Every rule/detector is readable code mapped to
   OWASP LLM Top 10 (2025), OWASP Agentic ASI01–ASI10, NIST AI RMF, MITRE ATLAS,
   and the AWS SRA for AI.
4. **AWS-native AIDR as a first-class citizen** — Security Hub, GuardDuty
   ingestion, SNS, EventBridge, Bedrock Guardrails, X-Ray — not an external bolt-on.
5. **Objective, reproducible red-team benchmark** built in.
6. **Accelerator** — a starting point teams own and customize.

## Where commercial leaders clearly lead (do not overstate)

- **Platform breadth** (SaaS + multi-cloud + endpoint) vs. our AWS-native scope.
- **Detection maturity** — deeper intent inference, richer multi-agent and
  context-drift modeling, proven at enterprise scale.
- **Operations** — managed service, SLAs, compliance attestations, dedicated
  threat research, autonomous response in production.

## Roadmap

Recently delivered (closing real gaps): **intent-based detection +
build-to-runtime correlation**, **Bedrock AgentCore** scanner + rules,
**Guardian** autonomous graduated response, **GuardDuty** ingestion, **agent
identity/NHI** analysis, **ASI01–ASI10** alignment.

Still open / honest gaps vs. the category leaders:
1. **Multi-platform** scanners (other SaaS/cloud agent platforms) — feasible as
   community plugins; not built here.
2. **Deeper multi-agent & context-drift modeling** (ASI06/ASI08/ASI10).
3. **Agentic supply chain (ASI04)** — MCP server/tool descriptor verification.
4. **Endpoint/device coverage** — out of scope for an AWS-native sample.

Because every capability is a plugin, closing these gaps is additive.
