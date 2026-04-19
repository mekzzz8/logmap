from .graph_model import GraphModel, Node, Edge, NodeType, RelationType, RiskLevel
from .entity_extractor import extract_entities
from .relationship_builder import build_edges

__all__ = [
    "build_graph",
    "GraphModel", "Node", "Edge",
    "NodeType", "RelationType", "RiskLevel",
]


def build_graph(events) -> GraphModel:
    nodes = extract_entities(events)
    edges = build_edges(events, nodes)
    return GraphModel(nodes=list(nodes.values()), edges=list(edges.values()))
