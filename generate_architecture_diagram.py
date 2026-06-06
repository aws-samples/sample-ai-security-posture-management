"""Generate the AI SPM architecture diagram as a PNG.

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

from diagrams import Cluster, Diagram, Edge
from diagrams.aws.compute import ECS, Fargate
from diagrams.aws.database import Dynamodb
from diagrams.aws.devtools import XRay
from diagrams.aws.ml import Sagemaker
from diagrams.aws.network import CloudFront, ELB
from diagrams.aws.security import Cognito
from diagrams.onprem.client import Users

OUTPUT = os.path.join(os.path.dirname(__file__), "spm-ui", "public", "architecture")

graph_attr = {
    "fontsize": "14",
    "bgcolor": "#0a0a0f",
    "fontcolor": "#e5e7eb",
    "pad": "0.8",
    "nodesep": "0.8",
    "ranksep": "1.0",
}
node_attr = {"fontsize": "11", "fontcolor": "#e5e7eb"}
edge_attr = {"color": "#4b5563", "fontsize": "9", "fontcolor": "#9ca3af"}

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
    users = Users("Security\nTeam")

    with Cluster("AWS Cloud", graph_attr={"bgcolor": "#111118", "fontcolor": "#6b7280", "style": "rounded", "pencolor": "#1f2937"}):

        with Cluster("CDN Layer", graph_attr={"bgcolor": "#13131d", "fontcolor": "#4b5563", "style": "rounded", "pencolor": "#1f2937"}):
            cf_spm = CloudFront("SPM\nDashboard")

        alb = ELB("Application\nLoad Balancer")
        cognito = Cognito("Cognito\nAuth")

        with Cluster("Monitored AI Platform (your environment)", graph_attr={"bgcolor": "#0f1520", "fontcolor": "#3b82f6", "style": "rounded", "pencolor": "#1e3a5f"}):
            workers = Fargate("AI Agents /\nWorkers")
            temporal = Fargate("Temporal\nServer")
            litellm = Fargate("LiteLLM\nGateway")

        with Cluster("AI SPM", graph_attr={"bgcolor": "#1a0f0f", "fontcolor": "#ef4444", "style": "rounded,bold", "pencolor": "#7f1d1d"}):

            with Cluster("Observe", graph_attr={"bgcolor": "#0f1520", "fontcolor": "#3b82f6", "style": "rounded", "pencolor": "#1e3a5f"}):
                scanner_litellm = ECS("LiteLLM\nScanner")
                scanner_temporal = ECS("Temporal\nScanner")
                scanner_xray = ECS("X-Ray\nScanner")

            with Cluster("Govern", graph_attr={"bgcolor": "#1a1508", "fontcolor": "#f59e0b", "style": "rounded", "pencolor": "#78350f"}):
                policy_engine = ECS("Policy Engine\n10 Rules")

            with Cluster("Defend", graph_attr={"bgcolor": "#1a0f0f", "fontcolor": "#ef4444", "style": "rounded", "pencolor": "#7f1d1d"}):
                callback = ECS("LiteLLM\nCallback")
                trace_analyzer = ECS("Trace\nAnalyzer")
                alert_engine = ECS("Alert\nCorrelation")

            spm_api = Fargate("SPM API\n:8001")
            spm_ui = Fargate("SPM UI\n:3001")

        bedrock = Sagemaker("Amazon\nBedrock")
        xray = XRay("AWS\nX-Ray")

        with Cluster("Data Layer", graph_attr={"bgcolor": "#13131d", "fontcolor": "#4b5563", "style": "rounded", "pencolor": "#1f2937"}):
            ddb_inventory = Dynamodb("Inventory")
            ddb_findings = Dynamodb("Findings")
            ddb_policies = Dynamodb("Policies")
            ddb_runtime = Dynamodb("Runtime\nEvents")

    # User flows
    users >> Edge(color="#ef4444", style="bold") >> cf_spm
    cf_spm >> Edge(color="#ef4444") >> alb
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

    # SPM API to data
    spm_api >> Edge(color="#4b5563") >> ddb_inventory
    spm_api >> Edge(color="#4b5563") >> ddb_findings
    spm_api >> Edge(color="#4b5563") >> ddb_policies
    spm_api >> Edge(color="#4b5563") >> ddb_runtime

    # ADOT to X-Ray
    workers >> Edge(style="dashed", color="#10b981", label="ADOT") >> xray

print(f"Diagram written to {OUTPUT}.png")
