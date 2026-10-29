#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# AI SPM - Deployment script
# ============================================================
# Builds the SPM API + UI container images, pushes them to ECR, and deploys the
# two CloudFormation stacks as an extension into your EXISTING AWS environment
# (VPC, ECS cluster, ALB, Cloud Map namespace) that runs your AI platform.
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
#     ECS_TASK_EXECUTION_ROLE_ARN  arn:aws:iam::...:role/...
#     SERVICE_DISCOVERY_NS_ID    Cloud Map private namespace ID (ns-...)
#     ALB_ARN                    arn:aws:elasticloadbalancing:...
#     ALB_DNS_NAME               internal/public ALB DNS name
#
#   Recommended:
#     COGNITO_USER_POOL_ID       enables dashboard auth (blank disables it)
#     COGNITO_CLIENT_ID
#     LITELLM_URL                e.g. http://litellm.<ns>.local:4000
#     LITELLM_MASTER_KEY         LiteLLM admin key (NoEcho; prefer Secrets Manager in prod)
#     TEMPORAL_ADDRESS           e.g. temporal.<ns>.local:7233
#
#   Optional (each grants the task role only the matching scoped permission):
#     SPM_CLASSIFIER_MODEL_ID    Bedrock model / inference profile for classifiers
#     SPM_CLASSIFIER_FOUNDATION_MODEL_ID  foundation model behind that profile
#     SPM_BEDROCK_GUARDRAIL_ID   guardrail for proxy enforcement (+ _VERSION)
#     SPM_SNS_TOPIC_ARN          SNS topic for high-severity alerts
#     SPM_EVENT_BUS_NAME         EventBridge bus for high-severity events
#     SPM_SECURITY_HUB_ENABLED   "true" exports findings to Security Hub
#     ENV_NAME                   resource/table prefix (default: ai-spm)
#     SPM_LISTENER_PORT          dedicated ALB listener port (default: 8090)
# ============================================================

: "${AWS_REGION:?Set AWS_REGION}"
: "${VPC_ID:?Set VPC_ID}"
: "${PRIVATE_SUBNET_IDS:?Set PRIVATE_SUBNET_IDS (comma-separated)}"
: "${ECS_CLUSTER_NAME:?Set ECS_CLUSTER_NAME}"
: "${ECS_SECURITY_GROUP_ID:?Set ECS_SECURITY_GROUP_ID}"
: "${ECS_TASK_EXECUTION_ROLE_ARN:?Set ECS_TASK_EXECUTION_ROLE_ARN}"
: "${SERVICE_DISCOVERY_NS_ID:?Set SERVICE_DISCOVERY_NS_ID}"
: "${ALB_ARN:?Set ALB_ARN}"
: "${ALB_DNS_NAME:?Set ALB_DNS_NAME}"

ENV_NAME="${ENV_NAME:-ai-spm}"
SPM_LISTENER_PORT="${SPM_LISTENER_PORT:-8090}"
COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID:-}"
COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-}"
LITELLM_URL="${LITELLM_URL:-}"
LITELLM_MASTER_KEY="${LITELLM_MASTER_KEY:-}"
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

# ============ Step 1: ECR repositories ============
echo "=== Step 1: ECR repositories ==="
for repo in "${ENV_NAME}-spm-api" "${ENV_NAME}-spm-ui"; do
  aws ecr create-repository --repository-name "$repo" --region "$AWS_REGION" >/dev/null 2>&1 || true
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

# ============ Step 3: Deploy CloudFormation ============
echo "=== Step 3: Deploy stack 01 (platform) ==="
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
    "EcsTaskExecutionRoleArn=${ECS_TASK_EXECUTION_ROLE_ARN}" \
    "ServiceDiscoveryNamespaceId=${SERVICE_DISCOVERY_NS_ID}" \
    "CognitoUserPoolId=${COGNITO_USER_POOL_ID}" \
    "CognitoClientId=${COGNITO_CLIENT_ID}" \
    "LiteLLMUrl=${LITELLM_URL}" \
    "LiteLLMMasterKey=${LITELLM_MASTER_KEY}" \
    "TemporalAddress=${TEMPORAL_ADDRESS}" \
    "ClassifierModelId=${SPM_CLASSIFIER_MODEL_ID}" \
    "ClassifierFoundationModelId=${SPM_CLASSIFIER_FOUNDATION_MODEL_ID}" \
    "BedrockGuardrailId=${SPM_BEDROCK_GUARDRAIL_ID}" \
    "BedrockGuardrailVersion=${SPM_BEDROCK_GUARDRAIL_VERSION}" \
    "AlertsSnsTopicArn=${SPM_SNS_TOPIC_ARN}" \
    "AlertsEventBusName=${SPM_EVENT_BUS_NAME}" \
    "SecurityHubExportEnabled=${SPM_SECURITY_HUB_ENABLED}"

echo "=== Step 4: Deploy stack 02 (CDN) ==="
aws cloudformation deploy \
  --stack-name "${ENV_NAME}-spm-cdn" \
  --template-file "$SCRIPT_DIR/infra/02-spm-cdn.yaml" \
  --region "$AWS_REGION" \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "EnvironmentName=${ENV_NAME}" \
    "AlbArn=${ALB_ARN}" \
    "AlbDnsName=${ALB_DNS_NAME}" \
    "ListenerPort=${SPM_LISTENER_PORT}"

DASH_URL=$(aws cloudformation describe-stacks --stack-name "${ENV_NAME}-spm-cdn" --region "$AWS_REGION" \
  --query 'Stacks[0].Outputs[?OutputKey==`SPMDashboardUrl`].OutputValue' --output text)

echo "============================================"
echo "  DEPLOYMENT COMPLETE"
echo "  Dashboard: ${DASH_URL}"
echo ""
echo "  Reminder: allow inbound on port ${SPM_LISTENER_PORT} on the ALB security"
echo "  group from the CloudFront origin-facing managed prefix list, and register"
echo "  the SPM callback in your LiteLLM config (see config/litellm-callback.example.yaml)."
echo "============================================"
