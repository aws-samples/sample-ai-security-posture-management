"""Generate the AI SPM architecture diagram as a PNG (light theme).

Requires the `diagrams` package (https://diagrams.mingrammer.com/) and Graphviz.

    pip install diagrams
    # macOS: brew install graphviz
    # Debian/Ubuntu: apt-get install graphviz

Usage:
    python generate_architecture_diagram.py

Output:
    spm-ui/public/architecture.png  (served by the dashboard's About page)
"""
import os

from diagrams import Cluster, Diagram, Edge, Node
from diagrams.aws.compute import ECS, Fargate
from diagrams.aws.database import Dynamodb
from diagrams.aws.devtools import XRay
from diagrams.aws.ml import Sagemaker
from diagrams.aws.network import CloudFront, ELB
from diagrams.aws.security import Cognito
from diagrams.onprem.client import Users

OUTPUT = os.path.join(os.path.dirname(__file__), "spm-ui", "public", "architecture")


def lab(text: str) -> str:
    """Prefix a blank line so the node label never overlaps the icon above it."""
    return "\n" + text


# ---- Light theme ----
graph_attr = {
    "fontsize": "30",
    "bgcolor": "#ffffff",
    "fontcolor": "#0f172a",
    "fontname": "Helvetica-Bold",
    "pad": "1.0",
    "nodesep": "1.0",
    "ranksep": "1.3",
    "dpi": "170",
    "splines": "spline",
}
node_attr = {
    "fontsize": "16",
    "fontcolor": "#0f172a",
    "fontname": "Helvetica-Bold",
}
edge_attr = {"color": "#94a3b8", "fontsize": "16", "fontcolor": "#334155", "fontname": "Helvetica"}


def cl(bg, fg, pen):
    """Cluster style helper (light tints)."""
    return {"bgcolor": bg, "fontcolor": fg, "pencolor": pen,
            "fontsize": "22", "fontname": "Helvetica-Bold", "style": "rounded",
            "penwidth": "2", "margin": "24"}


with Diagram(
    "AI Security Posture Management",
    filename=OUTPUT,
    outformat="png",
    show=False,
    direction="TB",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):
    # Headline value proposition banner (anchored above everything else)
    banner = Node(
        "AI SPM  —  Discover, assess & protect every AI agent\n"
        "100% AWS-native   •   no changes to agent code   •   monitor or enforce",
        shape="box", style="rounded,filled", fillcolor="#0f172a", color="#0f172a",
        fontcolor="#ffffff", fontsize="22", fontname="Helvetica-Bold",
        fixedsize="false", labelloc="c", width="0", height="0", margin="0.6,0.35",
    )
    users = Users(lab("Security Team"))
    banner >> Edge(style="invis") >> users

    with Cluster("AWS Cloud", graph_attr=cl("#f8fafc", "#64748b", "#cbd5e1")):

        with Cluster("CDN Layer", graph_attr=cl("#f5f3ff", "#6d28d9", "#c4b5fd")):
            cf_spm = CloudFront(lab("SPM Dashboard"))

        alb = ELB(lab("Application\nLoad Balancer"))
        cognito = Cognito(lab("Cognito Auth"))

        with Cluster("Monitored AI Platform (your environment)", graph_attr=cl("#eff6ff", "#1d4ed8", "#93c5fd")):
            workers = Fargate(lab("AI Agents /\nWorkers"))
            temporal = Fargate(lab("Temporal Server"))
            litellm = Fargate(lab("LiteLLM Gateway"))

        with Cluster("AI SPM  —  Observe • Govern • Defend", graph_attr=cl("#fef2f2", "#dc2626", "#fca5a5")):

            with Cluster("Observe\nFind every AI agent + shadow AI", graph_attr=cl("#eff6ff", "#1d4ed8", "#93c5fd")):
                scanner_litellm = ECS(lab("LiteLLM Scanner"))
                scanner_temporal = ECS(lab("Temporal Scanner"))
                scanner_xray = ECS(lab("X-Ray Scanner"))

            with Cluster("Govern\nOWASP • NIST AI RMF • MITRE ATLAS", graph_attr=cl("#fffbeb", "#b45309", "#fcd34d")):
                policy_engine = ECS(lab("Policy Engine\n10 Rules"))

            with Cluster("Defend\nBlock injection & data exfil in real time", graph_attr=cl("#fef2f2", "#dc2626", "#fca5a5")):
                callback = ECS(lab("LiteLLM Callback"))
                trace_analyzer = ECS(lab("Trace Analyzer"))
                alert_engine = ECS(lab("Alert Correlation"))

            spm_api = Fargate(lab("SPM API :8001"))
            spm_ui = Fargate(lab("SPM UI :3001"))

        bedrock = Sagemaker(lab("Amazon Bedrock"))
        xray = XRay(lab("AWS X-Ray"))

        with Cluster("Data Layer", graph_attr=cl("#f1f5f9", "#475569", "#cbd5e1")):
            ddb_inventory = Dynamodb(lab("Inventory"))
            ddb_findings = Dynamodb(lab("Findings"))
            ddb_policies = Dynamodb(lab("Policies"))
            ddb_runtime = Dynamodb(lab("Runtime Events"))

    # User flows
    users >> Edge(color="#ef4444", penwidth="2.5") >> cf_spm
    cf_spm >> Edge(color="#ef4444", penwidth="2") >> alb
    alb >> spm_ui
    alb >> spm_api
    spm_api >> Edge(style="dashed", color="#6366f1") >> cognito

    # Monitored platform internals
    workers >> temporal
    workers >> litellm
    litellm >> bedrock

    # Scanner data sources
    scanner_litellm >> Edge(color="#3b82f6", label="models\nkeys\nspend") >> litellm
    scanner_temporal >> Edge(color="#a855f7", label="workflows\nactivities") >> temporal
    scanner_xray >> Edge(color="#10b981", label="traces\ntopology") >> xray

    # Govern
    policy_engine >> Edge(color="#f59e0b") >> ddb_findings

    # Defend
    callback >> Edge(color="#ef4444", label="intercept") >> litellm
    trace_analyzer >> Edge(color="#ef4444") >> xray
    alert_engine >> Edge(color="#ef4444") >> ddb_runtime

    # SPM API to data stores
    spm_api >> Edge(color="#94a3b8") >> ddb_inventory
    spm_api >> Edge(color="#94a3b8") >> ddb_findings
    spm_api >> Edge(color="#94a3b8") >> ddb_policies
    spm_api >> Edge(color="#94a3b8") >> ddb_runtime

    # ADOT telemetry to X-Ray
    workers >> Edge(style="dashed", color="#10b981", label="ADOT") >> xray

print(f"Diagram written to {OUTPUT}.png")
