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
4. Turn on AI SPM **enforce mode** once detections are validated in monitor mode.
5. Export findings to **Security Hub** (`SPM_SECURITY_HUB_ENABLED=true`) and
   route high-severity events to **SNS/EventBridge** for response.
6. Re-run the **red-team benchmark** to confirm coverage.
