# AI SPM — Architecture

## 1. Overview

AI Security Posture Management (AI SPM) is an AWS-native security tool for AI
agent platforms. It discovers AI agents, assesses their posture against security
policies, and monitors them at runtime. It is designed to deploy as an
**extension** into an existing environment that already runs:

- A **LiteLLM** proxy fronting Amazon Bedrock (or other providers)
- A **Temporal** server orchestrating agent workflows (optional)
- An **OpenTelemetry → ADOT → AWS X-Ray** tracing pipeline

AI SPM never calls model providers directly for application traffic; it observes
the platform through admin APIs, the Temporal SDK, X-Ray, and an optional inline
LiteLLM callback.

## 2. The three pillars

### Observe
Scanners run on a schedule and on demand:

| Scanner | Source | Discovers |
|---------|--------|-----------|
| `litellm_scanner` | LiteLLM admin API | Models, keys, budgets, spend |
| `temporal_scanner` | Temporal SDK | Workflow types, execution + failure stats |
| `xray_scanner` | X-Ray `GetServiceGraph`, `GetTraceSummaries`, `BatchGetTraces` | Service topology + per-agent behavioral baselines |
| `aws_platform_scanner` | Bedrock, SageMaker, Lambda, CloudTrail | Bedrock agents, SageMaker endpoints, AI Lambdas, shadow-AI |

The orchestrator merges results, computes deltas (new/changed/removed), and
stores an inventory plus a topology snapshot in DynamoDB.

### Govern
The policy engine evaluates each inventory item against 10 rules (5
config-based, 5 trace-based) and writes `Finding` records tagged with the OWASP
LLM Top 10, NIST AI RMF, and MITRE ATLAS frameworks. Findings have a lifecycle:
`open → acknowledged → resolved`.

### Defend
Two complementary detection paths:

1. **Inline (LiteLLM callback / transparent proxy):** intercepts requests for
   prompt injection (regex + optional Bedrock semantic classifier), rate limits,
   memory poisoning, and scans responses for PII/secrets and MCP tool usage. In
   `enforce` mode it blocks; in `monitor` mode it logs.
2. **Behavioral (X-Ray trace analyzer):** learns a baseline of service-graph
   edges and per-span latency, then alerts on genuinely new edges and latency
   anomalies. A correlation engine groups multi-signal attack chains.

## 3. Components

| Service | Runtime | Port | Notes |
|---------|---------|------|-------|
| SPM API | ECS Fargate (FastAPI, ARM64) | 8001 | REST API + background monitor loop |
| SPM UI | ECS Fargate (Next.js, ARM64) | 3001 | Dashboard |
| DynamoDB | 4 tables | — | inventory, findings, policies, runtime-events (TTL) |

The API runs a background monitor loop (`spm/defender/monitor.py`) that polls
LiteLLM spend logs and X-Ray traces, periodically re-runs discovery and policy
evaluation, and performs privilege-escalation and attack-chain correlation.

## 4. Data model (DynamoDB)

| Table | Key | Contents |
|-------|-----|----------|
| `<env>-spm-inventory` | `agent_id` (+ `source-index`) | Discovered agents + topology snapshot |
| `<env>-spm-findings` | `finding_id` (+ `agent_id-index`) | Policy findings |
| `<env>-spm-policies` | `policy_id` | Rule toggles + defender config |
| `<env>-spm-runtime-events` | `event_id` (+ `agent_id-index`) | Runtime events with 30-day TTL |

## 5. Networking & delivery

AI SPM registers two ECS services behind a dedicated HTTPS ALB listener (default
port `8090`, TLS 1.2+ via `ELBSecurityPolicy-TLS13-1-2-2021-06`). A CloudFront
distribution on your dashboard hostname (ACM certificate, TLS 1.2+ for viewers)
sits in front of the listener and connects to the ALB over HTTPS only, using an
origin hostname that matches the ALB certificate: `/spm/*` routes to the SPM
API, everything else to the SPM UI. CloudFront access logs go to an encrypted,
non-public S3 bucket. The ALB security group must allow inbound on the listener
port from the CloudFront origin-facing managed prefix list.

## 6. IAM

The SPM task role grants:

- DynamoDB CRUD on the four SPM tables and their indexes only, plus use of the
  tables' customer managed KMS key only when DynamoDB calls KMS on the role's
  behalf (`kms:ViaService`).
- X-Ray segment and telemetry writes through the AWS managed
  `AWSXRayDaemonWriteAccess` policy, and X-Ray read (`GetTraceSummaries`,
  `BatchGetTraces`, `GetServiceGraph`).
- `bedrock:InvokeModel` only on the classifier inference profile
  (`ClassifierModelId`) and its foundation model (`ClassifierFoundationModelId`).
- `bedrock:ApplyGuardrail` only on `BedrockGuardrailId`, and only when it is set.
- `sns:Publish`, `events:PutEvents` and `securityhub:BatchImportFindings` only
  on the topic, event bus and Security Hub product you configure, and only when
  that integration is enabled.
- Read-only discovery and inspection: Bedrock / AgentCore List and Get calls,
  `sagemaker:ListEndpoints`, `lambda:ListFunctions`, `cloudtrail:LookupEvents`,
  GuardDuty List/Get and IAM role/policy Get calls.

`Resource: '*'` is used only for the X-Ray read calls and the read-only
discovery and inspection calls. Those actions list or describe resources
across the account, so they can't be limited to ARNs known at deploy time.

## 7. Extensibility

- **New scanners:** add a module under `spm/scanner/` returning
  `AgentInventoryItem` dicts and wire it into `orchestrator.run_scan`.
- **New rules:** add a check function + entry to `RULES` in
  `spm/engine/policy_engine.py`.
- **New detectors:** add to `spm/defender/advanced_detectors.py` and call from
  the transparent proxy / callback.
- **Environment knowledge:** supply `SPM_CONFIG_FILE` to teach the engine your
  expected workflows and dependency baselines.
