# Amazon Bedrock Security with AI SPM

AI SPM provides deep, Bedrock-native security coverage across all three pillars.
Because Bedrock is where the models, guardrails, agents, and knowledge bases
actually live, this is where AI SPM goes deepest.

## Observe — Bedrock discovery

The `builtin.bedrock_security` scanner (`spm/scanner/bedrock_scanner.py`)
discovers and inventories:

| Resource | What's captured |
|----------|-----------------|
| **Guardrails** | content-filter strengths (input/output), sensitive-information (PII) policy, denied topics, word filters, status |
| **Knowledge Bases (RAG)** | status, IAM role, customer-managed KMS encryption |
| **Model-invocation logging** | whether prompt/response logging is enabled and to which destinations (CloudWatch/S3) |

The `aws_platform_scanner` additionally discovers **Bedrock Agents**, **SageMaker
endpoints**, **AI Lambdas**, and **shadow AI** (Bedrock `InvokeModel` calls from
unknown IAM principals via CloudTrail).

## Govern — Bedrock posture rules

| Rule | Severity | Checks |
|------|----------|--------|
| `bedrock_logging_disabled` | High | Model-invocation logging is off (no audit trail) |
| `guardrail_no_pii_filter` | Medium | Guardrail lacks a sensitive-information (PII) policy |
| `guardrail_weak_content_filter` | Medium/Low | Content filters missing or below HIGH strength |
| `knowledge_base_unencrypted` | Medium | RAG knowledge base not encrypted with a customer-managed KMS key |
| `bedrock_agent_no_guardrail` | High | Bedrock Agent has no guardrail associated |
| `missing_guardrail_association` | Medium | Model/key has no guardrail (when `SPM_REQUIRE_GUARDRAIL=true`) |
| `unapproved_model` | Medium | Model outside `SPM_APPROVED_MODELS` allowlist |

Findings are tagged to OWASP LLM Top 10 (2025), NIST AI RMF, and MITRE ATLAS.

## Amazon Bedrock AgentCore

A dedicated `builtin.bedrock_agentcore` scanner (using the
`bedrock-agentcore-control` APIs) discovers and assesses:

| Resource | Captured | Rules |
|----------|----------|-------|
| Agent Runtimes | inbound authorizer, execution role, network config | `agentcore_runtime_no_authorizer` (High, ASI03) |
| Gateways (MCP) | authorizer type, KMS encryption, exception level, role | `agentcore_gateway_no_auth` (High, ASI04/ASI07), `agentcore_gateway_unencrypted` (Medium), `agentcore_gateway_debug_errors` (Low) |
| Memories | status | (inventory) |

AgentCore runtimes/gateways carry an execution `roleArn`, so they are also
covered by the agent identity / NHI rule (`excessive_agent_privilege`, ASI03).

## Defend — Bedrock-native runtime controls

* **Amazon Bedrock Guardrails enforcement** (`builtin.bedrock_guardrail`
  detector): calls `ApplyGuardrail` on inbound prompts and outbound responses
  for content filtering, denied topics, and PII detection/redaction. Set
  `SPM_BEDROCK_GUARDRAIL_ID` (and optionally `SPM_BEDROCK_GUARDRAIL_VERSION`).
  A guardrail intervention blocks the request in `enforce` mode.
* **Bedrock-powered semantic injection** (`builtin.semantic_injection`): uses a
  Bedrock model (`SPM_CLASSIFIER_MODEL_ID`) to classify prompts that the regex
  layer missed.
* **Optional OSS ensemble** (`pip install "ai-spm[security]"`): ProtectAI LLM
  Guard (ML prompt-injection, secrets) and Microsoft Presidio (PII) run as
  additional detectors when installed.

## Measure — red-team benchmark

`POST /spm/api/redteam/run` executes a curated attack corpus (injection,
jailbreak, system-prompt extraction, memory poisoning, data exfiltration,
insecure output) plus benign controls against your live detector stack and
returns a **defense-effectiveness score** with per-category detection rates and
a false-positive rate. Run it after enabling Bedrock Guardrails / the OSS
ensemble to quantify the improvement.

## IAM

The SPM task role (see `infra/01-spm-platform.yaml`) grants read-only Bedrock
posture access plus `bedrock:ApplyGuardrail`:

```
bedrock:ListGuardrails, bedrock:GetGuardrail,
bedrock:GetModelInvocationLoggingConfiguration,
bedrock:ListKnowledgeBases, bedrock:GetKnowledgeBase,
bedrock:ListAgents, bedrock:InvokeModel, bedrock:ApplyGuardrail
```

Scope these to specific guardrail/KB/agent ARNs for least privilege.

## Recommended hardening checklist

1. Enable **model-invocation logging** to CloudWatch + S3 (KMS-encrypted).
2. Attach a **guardrail** to every model/agent: content filters at **HIGH**, a
   **PII** policy, and **denied topics** for your domain.
3. Encrypt **knowledge bases** and their vector stores with **customer-managed
   KMS** keys; restrict the KB IAM role to least privilege.
4. Apply **least agency** to agent execution roles — no admin/wildcards; give
   each agent its own scoped, time-bound identity (enable `SPM_ANALYZE_IDENTITY`
   to detect violations).
5. **Network-isolate** Bedrock access via interface VPC endpoints (PrivateLink);
   keep agents in private subnets.
6. Turn on AI SPM **enforce mode** once detections are validated in monitor mode.
7. Export findings to **Security Hub** (`SPM_SECURITY_HUB_ENABLED=true`), ingest
   **GuardDuty AI Protection** findings (`SPM_GUARDDUTY_ENABLED=true`), and route
   high-severity events to **SNS/EventBridge**.
8. Re-run the **red-team benchmark** to confirm coverage.

## Alignment with the AWS SRA for AI

This coverage maps to the
[AWS Security Reference Architecture (SRA) for AI](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture-generative-ai/gen-ai-sra.html),
which defines six Bedrock security capabilities:

| AWS SRA for AI capability | AI SPM coverage |
|---------------------------|-----------------|
| 1. Secure model inference (IAM, I/O validation) | Guardrails enforcement + injection/PII detectors; key/model posture rules |
| 2. Secure model customization | Unapproved-model rule (supply chain, ASI04) |
| 3. Secure access to data (RAG) | Knowledge-base KMS encryption rule; data-exfiltration detector |
| 4. Secure tool usage | MCP/tool detection; excessive-agency rule (ASI02) |
| 5. Secure agents | Bedrock-agent guardrail rule; agent identity/NHI rule (ASI03) |
| 6. Secure AI applications | Logging, Security Hub/GuardDuty/SNS integration, runtime monitoring |

Cross-cutting SRA themes — **logging/monitoring**, **data protection (KMS)**,
**input/output validation (guardrails)**, **IAM least privilege**, and **network
isolation** — are each represented by a scanner, rule, or detector above.
