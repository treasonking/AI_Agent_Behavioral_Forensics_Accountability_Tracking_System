from typing import Dict, List, Optional

try:
    import networkx as nx
except ImportError:  # pragma: no cover
    nx = None

from backend.app.models.schemas import ForensicEvent


class CausalGraphBuilder:
    """Convert a session timeline into node-edge JSON."""

    def _find_root_cause(self, events: List[ForensicEvent]) -> Optional[str]:
        for event in events:
            if event.responsibility_type == "DOCUMENT_INDUCED":
                return event.event_id
            if "PROMPT_INJECTION_ATTEMPT" in event.reason_codes:
                return event.event_id
        return events[0].event_id if events else None

    def build_graph(self, events: List[ForensicEvent]) -> Dict:
        nodes = [
            {
                "id": event.event_id,
                "label": event.event_type,
                "risk_level": event.risk_level,
                "responsibility_type": event.responsibility_type,
            }
            for event in events
        ]

        edges = []
        previous_event_id = None
        for event in events:
            source = event.triggered_by_event_id or previous_event_id
            if source:
                edges.append(
                    {
                        "source": source,
                        "target": event.event_id,
                        "relation": "triggered" if event.triggered_by_event_id else "sequential",
                    }
                )
            previous_event_id = event.event_id

        root_cause_event_id = self._find_root_cause(events)
        graph = {
            "nodes": nodes,
            "edges": edges,
            "root_cause_event_id": root_cause_event_id,
        }

        if nx is not None:
            graph_obj = nx.DiGraph()
            graph_obj.add_nodes_from((node["id"], node) for node in nodes)
            graph_obj.add_edges_from((edge["source"], edge["target"], edge) for edge in edges)
            graph["node_count"] = graph_obj.number_of_nodes()
            graph["edge_count"] = graph_obj.number_of_edges()

        return graph
