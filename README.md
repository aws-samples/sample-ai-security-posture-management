# AI Security Posture Management (AI SPM) on AWS

Discover, assess, and protect the AI agents running in your environment — built
entirely on AWS-native services. AI SPM connects to a
[LiteLLM](https://docs.litellm.ai/) gateway, [Temporal](https://temporal.io/),
and [AWS X-Ray](https://docs.aws.amazon.com/xray/) to give security teams a
single dashboard across three pillars:

- **Observe** — continuous discovery and inventory of AI agents (LiteLLM models
  and keys, Temporal workflows, Bedrock agents, SageMaker endpoints, AI Lambdas),
  enriched with X-Ray behavioral baselines and a live service-dependency graph.
- **Govern** — a policy engine that evaluates agent configuration and
  trace-derived behavior against 10 built-in rules mapped to **OWASP LLM Top 10**,
  **NIST AI RMF**, and **MITRE ATLAS**.
- **Defend** — runtime threat detection (prompt injection, data exfiltration,
  memory poisoning, rate limiting, anomalous topology) via a LiteLLM callback and
  X-Ray trace analysis, with configurable **monitor** or **enforce** (inline
  blocking) modes.

![AI SPM Architecture](spm-ui/public/architecture.png)

> **Sample code, not production-ready.** This is sample code, for non-production
> usage. You should work with your security and legal teams to meet your
> organizational security, regulatory and compliance requirements before
> deployment. Review the [Security](#security) section before any use beyond
> evaluation.

## Featured use case — Group Sales & Event Management with AI Planning (Hospitality)

Hotels, resorts, and convention venues increasingly run **group sales and event
management** with multi-agent AI: an inbound RFP for a conference, wedding, or
corporate offsite kicks off cooperating agents that qualify the lead, check space
and room availability, build menus, draft the banquet event order, price the
package, and generate a proposal — pulling from the PMS, CRM, catering, and
payment systems.

These agents are autonomous, **highly privileged** (guest PII, negotiated
pricing, contracts, payments), and ingest **untrusted inbound content** (RFP
emails and documents) — the precise risk profile AI SPM is built to **Observe,
Govern, and Defend**. A malicious instruction hidden in an RFP, an over-permissive
sales key, or a planning agent that suddenly reaches a payment API are all
detectable here.

A ready-to-run baseline is included so you can see this end to end:

```bash
export SPM_CONFIG_FILE="$(pwd)/config/hospitality-group-sales.example.json"
```

- **Config:** [`config/hospitality-group-sales.example.json`](config/hospitality-group-sales.example.json)
  (9 group-sales/event workflows + their allowed dependencies)
- **Full write-up:** [`docs/use-cases/group-sales-event-management.md`](docs/use-cases/group-sales-event-management.md)

## Architecture

AI SPM deploys as an **extension** to an existing AWS environment. It does not
create a VPC, ECS cluster, or ALB — you provide those as parameters and AI SPM
adds its own ECS services, DynamoDB tables, IAM role, ALB listener, and
CloudFront distribution.

| Component | Service | Purpose |
|-----------|---------|---------|
| SPM API | ECS Fargate (FastAPI) | Discovery, policy evaluation, runtime monitoring, REST API |
| SPM UI | ECS Fargate (Next.js) | Security dashboard |
| Data | DynamoDB (4 tables) | Inventory, findings, policies, runtime events (TTL) |
| Auth | Amazon Cognito (created by the stack) | Dashboard/API authentication, admin-created users, TOTP MFA |
| Edge | CloudFront + ALB | Dashboard delivery |
| Telemetry | AWS X-Ray + ADOT | Trace ingestion and behavioral baselines |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details and data flows.

## Prerequisites

This is an extension, so it requires an existing platform to monitor:

- An **AWS account** with permissions to create DynamoDB, ECS, IAM, ELB, and
  CloudFront resources.
- An existing **VPC** with private subnets (NAT gateway or VPC endpoints for
  outbound AWS API access).
- An existing **ECS Fargate cluster**, **Application Load Balancer**, an ECS
  **security group**, and a **Cloud Map** private DNS namespace. The stack
  creates its own ECS task execution role.
- A **LiteLLM** proxy and (optionally) a **Temporal** server to discover.
- **Amazon Bedrock** model access for the optional semantic injection classifier.
- A **DNS domain** you control and two **ACM certificates**: one in `us-east-1`
  for the dashboard hostname (CloudFront), and one in your deployment Region for
  an origin hostname that points at your ALB. Traffic is HTTPS (TLS 1.2+) from
  the browser to CloudFront and from CloudFront to the ALB.
- An existing **S3 server access log bucket** in the deployment Region (for
  example a central log-archive bucket) whose bucket policy lets
  `logging.s3.amazonaws.com` write objects. The CloudFront access-log bucket
  sends its own S3 access logs there.
- Tooling: `aws` CLI, `finch` or `docker`, Python 3.11+, Node.js 20+.

## Repository layout

```
.
├── spm/                       # Python backend (FastAPI)
│   ├── api/main.py            # REST API + transparent LLM proxy
│   ├── core/                  # db, models, auth (Cognito), tracing, config
│   ├── scanner/               # LiteLLM / Temporal / X-Ray / AWS discovery
│   ├── engine/policy_engine.py# 10 Govern rules
│   └── defender/              # runtime monitoring, detectors, correlation
├── spm-ui/                    # Next.js dashboard
├── infra/
│   ├── 00-spm-identity.yaml   # Cognito user pool, app client, groups
│   ├── 01-spm-platform.yaml   # tables, IAM, ECS services, target groups
│   ├── 02-spm-cdn.yaml        # ALB listener + CloudFront
│   └── 03-spm-waf.yaml        # AWS WAF web ACL for CloudFront (us-east-1)
├── config/
│   ├── spm-config.example.json            # KNOWN_WORKFLOWS / EXPECTED_DEPS (generic)
│   ├── hospitality-group-sales.example.json # Featured hospitality use-case baseline
│   └── litellm-callback.example.yaml      # how to register the Defend callback
├── docs/
│   ├── ARCHITECTURE.md
│   └── use-cases/group-sales-event-management.md  # Featured use case
├── Dockerfile.spm-api
├── deploy.sh
├── generate_architecture_diagram.py
└── .env.example
```

## Quick start

### 1. Run the backend locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .

# Point at your platform (DynamoDB tables must exist, or use a local mock)
export AWS_REGION=us-east-1
export LITELLM_URL=http://localhost:4000
export LITELLM_KEY=your-litellm-admin-key
export TEMPORAL_ADDRESS=localhost:7233
# Local development only: without Cognito the API rejects every request unless
# you opt out explicitly. spm.api.serve binds to 127.0.0.1 and refuses to start
# with auth off on any other address or inside ECS.
export SPM_AUTH_DISABLED=true
export SPM_CORS_ORIGINS=http://localhost:3001   # lets the local dashboard call the API

python -m spm.api.serve   # 127.0.0.1, port 8001
# Health check:
curl localhost:8001/spm/health
```

### 2. Run the dashboard locally

```bash
cd spm-ui
npm install
export NEXT_PUBLIC_API_URL=http://localhost:8001
export NEXT_PUBLIC_COGNITO_POOL_ID=...   # e.g. outputs of the identity stack (required to build)
export NEXT_PUBLIC_COGNITO_CLIENT_ID=...
npm run dev   # http://localhost:3001
```

### 3. Deploy to AWS

```bash
cp .env.example .env
# edit .env with your VPC, subnets, cluster, ALB, domain + ACM certificates,
# LiteLLM, etc.
source .env
./deploy.sh
```

`deploy.sh` builds and pushes the two images to ECR, stores the LiteLLM key in
AWS Secrets Manager, and deploys three CloudFormation stacks (platform, WAF in
`us-east-1`, CDN). After it completes:

1. Create the two DNS records the script prints: the dashboard hostname to the
   CloudFront distribution, and the origin hostname to your ALB.
2. Allow inbound on the SPM listener port (default `8090`, HTTPS) on your ALB
   security group from the CloudFront origin-facing managed prefix list.
3. Create dashboard users (see [Users](#users)).
4. Register the Defend callback in your LiteLLM config (see
   [`config/litellm-callback.example.yaml`](config/litellm-callback.example.yaml)).

### Users

`infra/00-spm-identity.yaml` creates the Cognito user pool, already hardened:

| Setting | Value |
|---------|-------|
| Self-registration | Off (`AllowAdminCreateUserOnly: true`): only administrators create users |
| MFA | Required for every sign-in (TOTP authenticator app; SMS is not used) |
| Threat protection | `ENFORCED` by default: risky sign-ins are challenged or blocked and compromised credentials are detected. Needs the Cognito Plus plan (billed per monthly active user); set `SPM_COGNITO_THREAT_PROTECTION=AUDIT` or `OFF` to change it |
| Password policy | 14+ characters with upper, lower, number and symbol; temporary passwords expire in 1 day |
| ID / access token lifetime | 15 minutes, so removing a user from a group takes effect within 15 minutes |
| Refresh token lifetime | 8 hours; then the user signs in again with MFA |
| Groups | `spm-admins`, `spm-viewers` |
| Deletion protection | On; the pool is retained when the stack is deleted |

The API authorizes requests by Cognito group, read from the ID token:

| Group | Access |
|-------|--------|
| `spm-viewers` | Read-only: dashboard, inventory, findings, policies, runtime events |
| `spm-admins` | Everything, including scans, policy and defender changes, remediation, purge, red-team and integrations |

Users in neither group get `403`. Create a user and add them to a group:

```bash
POOL=$(aws cloudformation describe-stacks --stack-name ai-spm-spm-identity --region "$AWS_REGION" \
  --query 'Stacks[0].Outputs[?OutputKey==`UserPoolId`].OutputValue' --output text)
aws cognito-idp admin-create-user --user-pool-id "$POOL" --username alice@example.com \
  --user-attributes Name=email,Value=alice@example.com Name=email_verified,Value=true \
  --desired-delivery-mediums EMAIL
aws cognito-idp admin-add-user-to-group --user-pool-id "$POOL" \
  --username alice@example.com --group-name spm-admins
```

Cognito emails a temporary password. On first sign-in the dashboard asks the
user to set a permanent password and enroll an authenticator app; every later
sign-in asks for a TOTP code.

## Configuration

All configuration is via environment variables (12-factor). Key ones:

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT_NAME` | `ai-spm` | Prefix for DynamoDB table names |
| `LITELLM_URL` | `http://localhost:4000` | LiteLLM proxy base URL |
| `LITELLM_KEY` | _(empty)_ | LiteLLM admin key (deployed: injected from Secrets Manager) |
| `TEMPORAL_ADDRESS` | `localhost:7233` | Temporal frontend address |
| `AWS_REGION` | `us-east-1` | Region for boto3 clients |
| `COGNITO_POOL_ID` / `COGNITO_CLIENT_ID` | _(empty)_ | Cognito auth (set by the stack; empty = every request rejected with 503) |
| `SPM_ADMIN_GROUP` / `SPM_VIEWER_GROUP` | `spm-admins` / `spm-viewers` | Cognito groups for full and read-only access |
| `SPM_AUTH_DISABLED` | _(empty)_ | Set exactly `true` to turn auth off for **local development only**; the API refuses to start this way in ECS or on a non-loopback bind |
| `SPM_API_HOST` / `SPM_API_PORT` | `127.0.0.1` / `8001` | Bind address for `python -m spm.api.serve` (the container image sets `0.0.0.0`) |
| `SPM_PROXY_RATE_LIMIT_PER_MIN` | `120` | Transparent proxy: requests per LiteLLM key per minute (per API task) |
| `SPM_PROXY_IP_RATE_LIMIT_PER_MIN` | `600` | Transparent proxy: requests per client IP per minute (per API task) |
| `SPM_PROXY_KEY_CACHE_SEC` | `60` | How long a LiteLLM-validated proxy key is trusted before it is checked again |
| `SPM_API_DOCS` | _(empty)_ | Set `true` to serve `/docs` and `/openapi.json` (not routed by the ALB) |
| `SPM_CORS_ORIGINS` | _(empty)_ | Comma-separated exact origins allowed by CORS (`*` is ignored) |
| `SPM_CONFIG_FILE` | _(unset)_ | Path to JSON with `known_workflows` / `expected_dependencies` |
| `SPM_MONITORED_SERVICES` | _(empty)_ | Comma-separated service-name filter for new-dependency alerts |
| `SPM_CLASSIFIER_MODEL_ID` | `us.anthropic.claude-3-5-haiku-20241022-v1:0` | Bedrock model for semantic injection detection |
| `SPM_POLL_INTERVAL_SEC` | `10` | Runtime monitor poll interval |
| `SPM_PLUGINS` | _(empty)_ | Comma-separated import paths of third-party plugin modules (detectors/rules/scanners/sinks) |
| `SPM_BEDROCK_GUARDRAIL_ID` / `SPM_BEDROCK_GUARDRAIL_VERSION` | _(empty)_ / `DRAFT` | Enable Amazon Bedrock Guardrails enforcement in the proxy |
| `SPM_APPROVED_MODELS` | _(empty)_ | Comma-separated model allowlist for the `unapproved_model` rule |
| `SPM_REQUIRE_GUARDRAIL` | _(empty)_ | Set `true` to activate the `missing_guardrail_association` rule |
| `SPM_SECURITY_HUB_ENABLED` | _(empty)_ | Set `true` to export findings to AWS Security Hub (ASFF) |
| `SPM_GUARDDUTY_ENABLED` | _(empty)_ | Set `true` to ingest GuardDuty AI Protection findings |
| `SPM_ANALYZE_IDENTITY` | _(empty)_ | Set `true` to analyze agent execution-role privilege (ASI03; needs IAM read) |
| `SPM_GUARDIAN_MODE` | `off` | Guardian autonomous response: `off` / `recommend` / `auto` |
| `SPM_INTENT_LLM` | _(empty)_ | Set `true` to enable the Bedrock intent-alignment classifier |
| `SPM_INTENT_BASELINE_FACTOR` | `3.0` | Token-volume multiplier over baseline that flags behavioral drift |
| `SPM_SNS_TOPIC_ARN` | _(empty)_ | SNS topic for high-severity runtime alerts |
| `SPM_EVENT_BUS_NAME` | _(empty)_ | EventBridge bus for high-severity runtime events |

Environment-specific knowledge (which workflows you expect and their allowed
downstream dependencies) is optional and supplied via `SPM_CONFIG_FILE`. See
[`config/spm-config.example.json`](config/spm-config.example.json). Defaults are
empty so discovery works against any platform without configuration.

## Govern rules

Rules are registered plugins (see [Extensibility](#extensibility)) mapped to the
**OWASP LLM Top 10 (2025)**, **OWASP Agentic AI threats**, **NIST AI RMF**, and
**MITRE ATLAS**.

| Rule | Severity | Frameworks |
|------|----------|-----------|
| `overprivileged_key` | High | OWASP LLM06, Agentic T6, NIST |
| `unrestricted_model_access` | High | OWASP LLM06, MITRE, NIST |
| `missing_guardrails` | Medium | OWASP LLM10, NIST |
| `excessive_spend` | Medium | OWASP LLM10, NIST |
| `stale_agent` | Low | NIST |
| `high_retry_rate` | High | OWASP LLM10, NIST |
| `latency_anomaly` | Medium | MITRE |
| `excessive_llm_calls` | Medium | OWASP LLM06, Agentic T6, MITRE |
| `missing_trace_propagation` | Low | NIST |
| `unexpected_dependency` | High | Agentic T2, MITRE, OWASP LLM06 |
| `jailbreak_activity` | High | OWASP LLM01, Agentic T1, MITRE |
| `sensitive_data_exposure` | Critical | OWASP LLM02, MITRE, NIST |
| `insecure_output_handling` | High | OWASP LLM05, MITRE |
| `excessive_agency` | High | OWASP LLM06, Agentic T6, MITRE |
| `unapproved_model` | Medium | NIST, Agentic T15 |
| `missing_guardrail_association` | Medium | OWASP LLM01, NIST |

Plus **5 Amazon Bedrock posture rules** (guardrail strength/PII, knowledge-base
encryption, model-invocation logging, agent guardrail association) and an
**agent identity / NHI** rule (`excessive_agent_privilege`, ASI03) — see
[docs/bedrock-security.md](docs/bedrock-security.md). Inspect all loaded rules at
`GET /spm/api/plugins`.

## Runtime detectors (Defend)

Detectors are also plugins. Built-ins: regex + Bedrock-semantic **prompt
injection**, **jailbreak**, **system-prompt extraction**, **memory poisoning**,
**rate limiting**, **PII/secret exfiltration**, **insecure output handling**,
**MCP/tool usage**, **excessive agency**, and **Amazon Bedrock Guardrails**
(content filters, denied topics, PII redaction). Run in **monitor** or
**enforce** (inline blocking) mode.

Optionally layer a best-of-breed **OSS detection ensemble** (no vendor lock-in)
with `pip install "ai-spm[security]"`: ProtectAI **LLM Guard** (ML
prompt-injection + secrets) and Microsoft **Presidio** (PII). These register
automatically when installed and no-op when not.

### Intent-based detection + build-to-runtime correlation

The `intent_alignment` detector infers whether an agent's **runtime behavior**
matches how it was **built/configured**: it correlates the model, tools, and
token usage seen at runtime against the agent's inventory record (sanctioned
models, expected dependencies, behavioral baseline) and tracks per-session
**intent/behavioral drift** (new models/tools appearing mid-session). An optional
Bedrock classifier (`SPM_INTENT_LLM=true`) judges whether an agent's action
summary aligns with its declared purpose.

### Guardian — autonomous graduated response

The Guardian orchestrator (`POST /spm/api/guardian/run`, gated by
`SPM_GUARDIAN_MODE` = `off` | `recommend` | `auto`) takes recent high/critical
events and applies a **proportional** response — alert → block → contain
(quarantine workflow / revoke model access) — executing via the existing
remediations and writing an audited `guardian_action` trail.

## Deep Amazon Bedrock security

A dedicated Bedrock scanner discovers **Guardrails** (filter strength, PII,
denied topics), **Knowledge Bases** (KMS encryption), **model-invocation
logging**, and **Bedrock Agents**, plus a **Bedrock AgentCore** scanner
(runtimes, MCP gateways, memories) — with Bedrock-specific Govern rules.
Full details: [docs/bedrock-security.md](docs/bedrock-security.md).

## Measure your defenses (red-team benchmark)

`POST /spm/api/redteam/run` runs a curated attack corpus (injection, jailbreak,
extraction, exfiltration, insecure output) plus benign controls against your
**live** detector stack and returns an objective **defense-effectiveness score**
— detection rate, false-positive rate, and per-category breakdown. Use it to
prove (not just claim) coverage before and after enabling Guardrails / the OSS
ensemble.

## AIDR integrations

High-severity findings and runtime events fan out to pluggable sinks for AI
Detection & Response: **AWS Security Hub** (ASFF `BatchImportFindings`),
**Amazon SNS**, and **Amazon EventBridge**. AI SPM also **ingests Amazon
GuardDuty AI Protection** findings (guardrail removal, disabled invocation
logging, anomalous Bedrock usage) via `POST /spm/api/integrations/guardduty/ingest`
(`SPM_GUARDDUTY_ENABLED=true`), and can analyze **agent execution-role privilege**
for non-human-identity risk (ASI03, `SPM_ANALYZE_IDENTITY=true`).

Standards alignment: rules are tagged to **OWASP LLM Top 10 (2025)**, the
**OWASP Top 10 for Agentic Applications (ASI01–ASI10, Dec 2025)**, **NIST AI
RMF**, **MITRE ATLAS**, and mapped to the **AWS SRA for AI**
([docs/bedrock-security.md](docs/bedrock-security.md)).

## Extensibility

AI SPM is extensible by design. Four decorator-based registries — **detectors**
(Defend), **rules** (Govern), **scanners** (Observe), and **sinks** (AIDR) — let
you add capabilities without modifying core code. Drop a module with your
decorated function anywhere importable and point `SPM_PLUGINS` at it:

```python
from spm.core.registry import detector, Detection

@detector("acme.secret_scanner", phases=("post",))
def scan_secrets(ctx):
    if "BEGIN RSA PRIVATE KEY" in ctx.response_text:
        return [Detection("private_key_leak", "critical", {"model": ctx.model}, block=True)]
    return []
```

```bash
SPM_PLUGINS="acme.spm_plugins" python -m spm.api.serve
```

Inspect everything that's loaded at `GET /spm/api/plugins`. Full guide:
[docs/extending.md](docs/extending.md). How it compares to commercial AI agent
security platforms: [docs/comparison.md](docs/comparison.md).

## Testing

```bash
pip install -r requirements-dev.txt   # test deps only; no pytest plugins needed
pytest -q
```

The suite (69 tests) covers authentication and authorization (real RS256
tokens, every route without a token, the reviewed public routes and read-only
GET routes, the auth-disabled loopback guards), the transparent proxy's key
checks and rate limits, the plugin registry, the detection logic against the
red-team corpus (asserts ≥80% recall and 0 false positives on benign controls),
intent detection and Guardian decisions, the risk scoring engine, and `db.py`
against moto-mocked DynamoDB. CI runs it on Python 3.11 to 3.14 on every push
and pull request (see `.github/workflows/tests.yml`).

## Security

- **Authentication (fail closed, default deny):** Authentication is a global
  FastAPI dependency, so every route needs a Cognito ID token unless it is one of
  three reviewed (path, method) pairs: `GET /spm/health`, and the VPC-only
  `POST /v1/chat/completions` and `GET /v1/models`. Any other method on those
  paths needs a token. Tests enumerate every route to enforce this. If
  `COGNITO_POOL_ID`/`COGNITO_CLIENT_ID` are unset the API rejects every request
  with `503`. `SPM_AUTH_DISABLED=true` turns auth off for local development
  only; the API refuses to start that way inside ECS or on a non-loopback bind,
  and in that mode it refuses every request whose connection is not loopback on
  both ends, however the server was started.
- **Identity:** The stack creates the Cognito pool with self-registration off,
  TOTP MFA required, threat protection enforced and 15-minute ID tokens (see
  [Users](#users)). Signing keys
  are fetched again (at most once a minute) when a token has an unknown key ID.
- **Authorization:** Read routes need the `spm-viewers` or `spm-admins` Cognito
  group; every state-changing or action-triggering route needs `spm-admins`.
  A test pins GET routes to a reviewed read-only list. Each allowed admin action
  and each denial is written to the `spm.audit` log.
- **Transparent proxy:** `/v1/chat/completions` rate-limits per key and per IP
  and validates the caller's key with LiteLLM before running any detector,
  writing any event, sending any alert or calling Bedrock. Post-response
  detection and events happen only when LiteLLM returns 2xx.
- **Browser:** The dashboard sends a per-request nonce-based
  Content-Security-Policy (`script-src 'nonce-…' 'strict-dynamic'`,
  `connect-src` limited to the origin and Cognito, `frame-ancestors 'none'`).
  CloudFront adds HSTS, `X-Content-Type-Options`, `X-Frame-Options: DENY` and a
  referrer policy. Tokens are kept in `sessionStorage` (cleared when the tab
  closes).
- **Secrets:** The LiteLLM master key is stored in **AWS Secrets Manager** and
  injected into the API container by ECS at start; it is not a CloudFormation
  parameter and does not appear in the task definition.
- **CORS:** Off by default (the dashboard and API share one origin). Set
  `SPM_CORS_ORIGINS` to a comma-separated list of exact origins if you need it;
  `*` is ignored.
- **Edge:** HTTPS (TLS 1.2+) from browser to CloudFront and from CloudFront to
  the ALB; AWS WAF (IP reputation, common rule set, known bad inputs, per-IP
  rate limit) on the distribution; CloudFront and S3 access logging.
- **Enforce mode:** Inline blocking (`/spm/api/defender/mode` = `enforce`) can
  reject live LLM traffic. Validate detection rules in `monitor` mode first.
- **Least privilege:** Write actions on the SPM task role are scoped to specific
  resources (DynamoDB tables, the KMS table key, the classifier model, and the
  guardrail / SNS topic / EventBridge bus / Security Hub product you configure).
  `Resource: '*'` remains only on read-only discovery, X-Ray read, IAM read and
  GuardDuty read actions, which enumerate resources account-wide. The task
  execution role can read only the LiteLLM key secret.
- **Data protection:** The SPM DynamoDB tables and CloudWatch log groups are
  encrypted with a customer managed KMS key (rotation enabled); the tables have
  point-in-time recovery enabled.
- **Supply chain:** Base images come from Amazon ECR Public; the UI image is
  built with `npm ci` from the committed lockfile; ECR repositories scan on push
  and use immutable tags.

See [CONTRIBUTING.md](CONTRIBUTING.md#security-issue-notifications) for how to
report security issues.

## Cleanup

```bash
aws cloudformation delete-stack --stack-name ai-spm-cdn --region "$AWS_REGION"
aws cloudformation delete-stack --stack-name ai-spm-waf --region us-east-1
aws cloudformation delete-stack --stack-name ai-spm-platform --region "$AWS_REGION"
aws cloudformation delete-stack --stack-name ai-spm-spm-identity --region "$AWS_REGION"
# The Cognito user pool is retained with deletion protection on. To remove it,
# turn deletion protection off in the Cognito console, then:
#   aws cognito-idp delete-user-pool --user-pool-id <id>
aws secretsmanager delete-secret --secret-id ai-spm/spm/litellm-master-key --region "$AWS_REGION"
# Optionally delete the ECR repositories: ai-spm-spm-api, ai-spm-spm-ui
# The KMS key (alias/ai-spm-spm-data) is retained on stack deletion so backups
# and logs stay decryptable; schedule its deletion when no longer needed.
# The CloudFront access-log bucket is also retained; empty and delete it when done.
```

## License

This library is licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file.
