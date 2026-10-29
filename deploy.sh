#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# AI SPM - Deployment script
# ============================================================
# Creates the Cognito user pool (stack 00), builds the SPM API + UI container
# images, pushes them to ECR, stores the LiteLLM key in AWS Secrets Manager, and
# deploys the remaining CloudFormation stacks as an extension into your EXISTING
# AWS environment (VPC, ECS cluster, ALB, Cloud Map namespace) that runs your AI
# platform.
#
# Configure via environment variables (or copy .env.example to .env and source
# it before running):
#
#   Required:
#     AWS_REGION                 e.g. us-east-1
#     VPC_ID                     e.g. vpc-0abc...
#     PRIVATE_SUBNET_IDS         comma-separated, e.g. subnet-a,subnet-b
#     ECS_CLUSTER_NAME           existing ECS cluster name
#     ECS_SECURITY_GROUP_ID      sg-... applied to the SPM tasks
#     SERVICE_DISCOVERY_NS_ID    Cloud Map private namespace ID (ns-...)
#     ALB_ARN                    arn:aws:elasticloadbalancing:...
#     SPM_DASHBOARD_DOMAIN       dashboard hostname, e.g. spm.example.com
#     SPM_CLOUDFRONT_CERT_ARN    ACM cert in us-east-1 covering SPM_DASHBOARD_DOMAIN
#     SPM_ORIGIN_DOMAIN          DNS name aliased to the ALB, e.g. spm-origin.example.com
#     SPM_ALB_CERT_ARN           ACM cert in AWS_REGION covering SPM_ORIGIN_DOMAIN
#     SPM_S3_ACCESS_LOGS_BUCKET  existing S3 server-access-log bucket in AWS_REGION
#
#   Recommended:
#     LITELLM_URL                e.g. http://litellm.<ns>.local:4000
#     LITELLM_MASTER_KEY         LiteLLM admin key; stored in Secrets Manager as
#                                <ENV_NAME>/spm/litellm-master-key (never passed
#                                to CloudFormation or the task definition)
#     SPM_LITELLM_KEY_SECRET_ARN use an existing secret instead of LITELLM_MASTER_KEY
#     TEMPORAL_ADDRESS           e.g. temporal.<ns>.local:7233
#
#   Optional (each grants the task role only the matching scoped permission):
#     SPM_CLASSIFIER_MODEL_ID    Bedrock model / inference profile for classifiers
#     SPM_CLASSIFIER_FOUNDATION_MODEL_ID  foundation model behind that profile
#     SPM_BEDROCK_GUARDRAIL_ID   guardrail for proxy enforcement (+ _VERSION)
#     SPM_SNS_TOPIC_ARN          SNS topic for high-severity alerts
#     SPM_EVENT_BUS_NAME         EventBridge bus for high-severity events
#     SPM_SECURITY_HUB_ENABLED   "true" exports findings to Security Hub
#     SPM_WAF_RATE_LIMIT         requests per IP per 5 minutes (default: 2000)
#     ENV_NAME                   resource/table prefix (default: ai-spm)
#     SPM_LISTENER_PORT          dedicated ALB listener port (default: 8090)
# ============================================================

: "${AWS_REGION:?Set AWS_REGION}"
: "${VPC_ID:?Set VPC_ID}"
: "${PRIVATE_SUBNET_IDS:?Set PRIVATE_SUBNET_IDS (comma-separated)}"
: "${ECS_CLUSTER_NAME:?Set ECS_CLUSTER_NAME}"
: "${ECS_SECURITY_GROUP_ID:?Set ECS_SECURITY_GROUP_ID}"
: "${SERVICE_DISCOVERY_NS_ID:?Set SERVICE_DISCOVERY_NS_ID}"
: "${ALB_ARN:?Set ALB_ARN}"
: "${SPM_DASHBOARD_DOMAIN:?Set SPM_DASHBOARD_DOMAIN (e.g. spm.example.com)}"
: "${SPM_CLOUDFRONT_CERT_ARN:?Set SPM_CLOUDFRONT_CERT_ARN (ACM cert in us-east-1)}"
: "${SPM_ORIGIN_DOMAIN:?Set SPM_ORIGIN_DOMAIN (DNS name aliased to the ALB)}"
: "${SPM_ALB_CERT_ARN:?Set SPM_ALB_CERT_ARN (ACM cert in AWS_REGION)}"
: "${SPM_S3_ACCESS_LOGS_BUCKET:?Set SPM_S3_ACCESS_LOGS_BUCKET (existing S3 access-log bucket)}"

ENV_NAME="${ENV_NAME:-ai-spm}"
SPM_LISTENER_PORT="${SPM_LISTENER_PORT:-8090}"
SPM_WAF_RATE_LIMIT="${SPM_WAF_RATE_LIMIT:-2000}"
LITELLM_URL="${LITELLM_URL:-}"
LITELLM_MASTER_KEY="${LITELLM_MASTER_KEY:-}"
SPM_LITELLM_KEY_SECRET_ARN="${SPM_LITELLM_KEY_SECRET_ARN:-}"
TEMPORAL_ADDRESS="${TEMPORAL_ADDRESS:-}"
SPM_CLASSIFIER_MODEL_ID="${SPM_CLASSIFIER_MODEL_ID:-us.anthropic.claude-3-5-haiku-20241022-v1:0}"
SPM_CLASSIFIER_FOUNDATION_MODEL_ID="${SPM_CLASSIFIER_FOUNDATION_MODEL_ID:-anthropic.claude-3-5-haiku-20241022-v1:0}"
SPM_BEDROCK_GUARDRAIL_ID="${SPM_BEDROCK_GUARDRAIL_ID:-}"
SPM_BEDROCK_GUARDRAIL_VERSION="${SPM_BEDROCK_GUARDRAIL_VERSION:-DRAFT}"
SPM_SNS_TOPIC_ARN="${SPM_SNS_TOPIC_ARN:-}"
SPM_EVENT_BUS_NAME="${SPM_EVENT_BUS_NAME:-}"
SPM_SECURITY_HUB_ENABLED="${SPM_SECURITY_HUB_ENABLED:-false}"
case "$SPM_SECURITY_HUB_ENABLED" in
  1|true|TRUE|yes|YES) SPM_SECURITY_HUB_ENABLED=true ;;
  *) SPM_SECURITY_HUB_ENABLED=false ;;
esac

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
CONTAINER_CMD=$(command -v finch || command -v docker)
TAG="deploy-$(date +%s)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================"
echo "  Deploying AI SPM"
echo "    Account:  $ACCOUNT_ID"
echo "    Region:   $AWS_REGION"
echo "    Env:      $ENV_NAME"
echo "    Builder:  $CONTAINER_CMD"
echo "============================================"

# ============ Step 0: Cognito user pool ============
# Self-registration off, TOTP MFA required, 15-minute ID tokens. The UI image is
# built with these IDs and stack 01 imports them.
echo "=== Step 0: Deploy stack 00 (identity) ==="
aws cloudformation deploy \
  --stack-name "${ENV_NAME}-spm-identity" \
  --template-file "$SCRIPT_DIR/infra/00-spm-identity.yaml" \
  --region "$AWS_REGION" \
  --no-fail-on-empty-changeset \
  --parameter-overrides "EnvironmentName=${ENV_NAME}"
COGNITO_USER_POOL_ID=$(aws cloudformation describe-stacks --stack-name "${ENV_NAME}-spm-identity" --region "$AWS_REGION" \
  --query 'Stacks[0].Outputs[?OutputKey==`UserPoolId`].OutputValue' --output text)
COGNITO_CLIENT_ID=$(aws cloudformation describe-stacks --stack-name "${ENV_NAME}-spm-identity" --region "$AWS_REGION" \
  --query 'Stacks[0].Outputs[?OutputKey==`UserPoolClientId`].OutputValue' --output text)

# ============ Step 1: ECR repositories ============
echo "=== Step 1: ECR repositories ==="
for repo in "${ENV_NAME}-spm-api" "${ENV_NAME}-spm-ui"; do
  aws ecr create-repository --repository-name "$repo" --region "$AWS_REGION" \
    --image-scanning-configuration scanOnPush=true \
    --image-tag-mutability IMMUTABLE >/dev/null 2>&1 || true
done
aws ecr get-login-password --region "$AWS_REGION" | "$CONTAINER_CMD" login --username AWS --password-stdin "$ECR"

# ============ Step 2: Build + push images (ARM64) ============
echo "=== Step 2: Build + push images ==="
echo "  Building SPM API..."
"$CONTAINER_CMD" build --platform linux/arm64 \
  -t "$ECR/${ENV_NAME}-spm-api:$TAG" -f "$SCRIPT_DIR/Dockerfile.spm-api" "$SCRIPT_DIR"
"$CONTAINER_CMD" push "$ECR/${ENV_NAME}-spm-api:$TAG"

echo "  Building SPM UI..."
"$CONTAINER_CMD" build --platform linux/arm64 \
  --build-arg NEXT_PUBLIC_COGNITO_POOL_ID="$COGNITO_USER_POOL_ID" \
  --build-arg NEXT_PUBLIC_COGNITO_CLIENT_ID="$COGNITO_CLIENT_ID" \
  -t "$ECR/${ENV_NAME}-spm-ui:$TAG" -f "$SCRIPT_DIR/spm-ui/Dockerfile" "$SCRIPT_DIR/spm-ui"
"$CONTAINER_CMD" push "$ECR/${ENV_NAME}-spm-ui:$TAG"

# ============ Step 3: LiteLLM key -> Secrets Manager ============
if [ -z "$SPM_LITELLM_KEY_SECRET_ARN" ] && [ -n "$LITELLM_MASTER_KEY" ]; then
  echo "=== Step 3: Store LiteLLM key in Secrets Manager ==="
  SECRET_NAME="${ENV_NAME}/spm/litellm-master-key"
  # Pass the value through a 0600 temp file so it never appears on a command line.
  umask 077
  SECRET_FILE="$(mktemp)"
  trap 'rm -f "$SECRET_FILE"' EXIT
  printf '%s' "$LITELLM_MASTER_KEY" > "$SECRET_FILE"
  if aws secretsmanager describe-secret --secret-id "$SECRET_NAME" --region "$AWS_REGION" >/dev/null 2>&1; then
    aws secretsmanager put-secret-value --secret-id "$SECRET_NAME" --region "$AWS_REGION" \
      --secret-string "file://$SECRET_FILE" >/dev/null
  else
    aws secretsmanager create-secret --name "$SECRET_NAME" --region "$AWS_REGION" \
      --description "LiteLLM master key used by AI SPM (${ENV_NAME})" \
      --secret-string "file://$SECRET_FILE" >/dev/null
  fi
  rm -f "$SECRET_FILE"
  SPM_LITELLM_KEY_SECRET_ARN=$(aws secretsmanager describe-secret --secret-id "$SECRET_NAME" \
    --region "$AWS_REGION" --query ARN --output text)
else
  echo "=== Step 3: LiteLLM key secret: ${SPM_LITELLM_KEY_SECRET_ARN:-none} ==="
fi

# ============ Step 4: Deploy CloudFormation ============
echo "=== Step 4: Deploy stack 01 (platform) ==="
aws cloudformation deploy \
  --stack-name "${ENV_NAME}-spm-platform" \
  --template-file "$SCRIPT_DIR/infra/01-spm-platform.yaml" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region "$AWS_REGION" \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "EnvironmentName=${ENV_NAME}" \
    "SPMAPIImage=${ECR}/${ENV_NAME}-spm-api:${TAG}" \
    "SPMUIImage=${ECR}/${ENV_NAME}-spm-ui:${TAG}" \
    "VpcId=${VPC_ID}" \
    "PrivateSubnetIds=${PRIVATE_SUBNET_IDS}" \
    "EcsClusterName=${ECS_CLUSTER_NAME}" \
    "EcsSecurityGroupId=${ECS_SECURITY_GROUP_ID}" \
    "ServiceDiscoveryNamespaceId=${SERVICE_DISCOVERY_NS_ID}" \
    "LiteLLMUrl=${LITELLM_URL}" \
    "LiteLLMKeySecretArn=${SPM_LITELLM_KEY_SECRET_ARN}" \
    "TemporalAddress=${TEMPORAL_ADDRESS}" \
    "ClassifierModelId=${SPM_CLASSIFIER_MODEL_ID}" \
    "ClassifierFoundationModelId=${SPM_CLASSIFIER_FOUNDATION_MODEL_ID}" \
    "BedrockGuardrailId=${SPM_BEDROCK_GUARDRAIL_ID}" \
    "BedrockGuardrailVersion=${SPM_BEDROCK_GUARDRAIL_VERSION}" \
    "AlertsSnsTopicArn=${SPM_SNS_TOPIC_ARN}" \
    "AlertsEventBusName=${SPM_EVENT_BUS_NAME}" \
    "SecurityHubExportEnabled=${SPM_SECURITY_HUB_ENABLED}"

echo "=== Step 5: Deploy stack 03 (WAF, us-east-1) ==="
aws cloudformation deploy \
  --stack-name "${ENV_NAME}-spm-waf" \
  --template-file "$SCRIPT_DIR/infra/03-spm-waf.yaml" \
  --region us-east-1 \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "EnvironmentName=${ENV_NAME}" \
    "RateLimitPer5Min=${SPM_WAF_RATE_LIMIT}"
WEB_ACL_ARN=$(aws cloudformation describe-stacks --stack-name "${ENV_NAME}-spm-waf" --region us-east-1 \
  --query 'Stacks[0].Outputs[?OutputKey==`WebAclArn`].OutputValue' --output text)

echo "=== Step 6: Deploy stack 02 (CDN) ==="
aws cloudformation deploy \
  --stack-name "${ENV_NAME}-spm-cdn" \
  --template-file "$SCRIPT_DIR/infra/02-spm-cdn.yaml" \
  --region "$AWS_REGION" \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "EnvironmentName=${ENV_NAME}" \
    "AlbArn=${ALB_ARN}" \
    "ListenerPort=${SPM_LISTENER_PORT}" \
    "DashboardDomainName=${SPM_DASHBOARD_DOMAIN}" \
    "CloudFrontCertificateArn=${SPM_CLOUDFRONT_CERT_ARN}" \
    "OriginDomainName=${SPM_ORIGIN_DOMAIN}" \
    "AlbCertificateArn=${SPM_ALB_CERT_ARN}" \
    "S3AccessLogsBucketName=${SPM_S3_ACCESS_LOGS_BUCKET}" \
    "WebAclArn=${WEB_ACL_ARN}"

DASH_URL=$(aws cloudformation describe-stacks --stack-name "${ENV_NAME}-spm-cdn" --region "$AWS_REGION" \
  --query 'Stacks[0].Outputs[?OutputKey==`SPMDashboardUrl`].OutputValue' --output text)
CF_DOMAIN=$(aws cloudformation describe-stacks --stack-name "${ENV_NAME}-spm-cdn" --region "$AWS_REGION" \
  --query 'Stacks[0].Outputs[?OutputKey==`SPMDistributionDomainName`].OutputValue' --output text)

echo "============================================"
echo "  DEPLOYMENT COMPLETE"
echo "  Dashboard: ${DASH_URL}"
echo ""
echo "  DNS (if not already in place):"
echo "    ${SPM_DASHBOARD_DOMAIN} -> ${CF_DOMAIN} (CNAME / Route 53 alias)"
echo "    ${SPM_ORIGIN_DOMAIN} -> your ALB DNS name (CNAME / Route 53 alias)"
echo ""
echo "  Users: create them as an administrator in user pool ${COGNITO_USER_POOL_ID}"
echo "  and add each to the spm-admins (full access) or spm-viewers (read-only)"
echo "  group. Each user sets a password and enrolls TOTP MFA at first sign-in."
echo "  See README > Users."
echo ""
echo "  Reminder: allow inbound on port ${SPM_LISTENER_PORT} on the ALB security"
echo "  group from the CloudFront origin-facing managed prefix list, and register"
echo "  the SPM callback in your LiteLLM config (see config/litellm-callback.example.yaml)."
echo "============================================"
