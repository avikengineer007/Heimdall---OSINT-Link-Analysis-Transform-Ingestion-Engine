"""
Graph Serializers and Exporters: JSON, GraphML, and Maltego (.mtgx).
"""

from __future__ import annotations

import io
import json
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, Dict, List
from heimdall.core.models import GraphEdge, GraphNode
from heimdall.graph.base import BaseGraphStore


class GraphExporter:
    """Exports graph structures into industry-standard formats."""

    @staticmethod
    def to_json(store: BaseGraphStore, indent: int = 2) -> str:
        """Serializes graph nodes and edges into JSON format."""
        nodes = store.get_nodes()
        edges = store.get_edges()

        data = {
            "meta": store.get_stats(),
            "nodes": [
                {
                    "id": n.urn,
                    "type": n.entity_type,
                    "value": n.value,
                    "properties": n.properties,
                }
                for n in nodes
            ],
            "links": [e.to_contract_dict() for e in edges],
        }
        return json.dumps(data, indent=indent, default=str)

    @staticmethod
    def to_graphml(store: BaseGraphStore) -> str:
        """Serializes graph to standard GraphML XML."""
        root = ET.Element(
            "graphml",
            {
                "xmlns": "http://graphml.graphdrawing.org/xmlns",
                "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                "xsi:schemaLocation": (
                    "http://graphml.graphdrawing.org/xmlns "
                    "http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd"
                ),
            },
        )

        # Attribute declarations
        ET.SubElement(root, "key", {"id": "d0", "for": "node", "attr.name": "type", "attr.type": "string"})
        ET.SubElement(root, "key", {"id": "d1", "for": "node", "attr.name": "value", "attr.type": "string"})
        ET.SubElement(root, "key", {"id": "d2", "for": "edge", "attr.name": "rel", "attr.type": "string"})
        ET.SubElement(root, "key", {"id": "d3", "for": "edge", "attr.name": "props", "attr.type": "string"})

        graph = ET.SubElement(root, "graph", {"id": "HeimdallGraph", "edgedefault": "directed"})

        # Nodes
        for node in store.get_nodes():
            node_el = ET.SubElement(graph, "node", {"id": node.urn})
            d0 = ET.SubElement(node_el, "data", {"key": "d0"})
            d0.text = node.entity_type
            d1 = ET.SubElement(node_el, "data", {"key": "d1"})
            d1.text = node.value

        # Edges
        for i, edge in enumerate(store.get_edges()):
            edge_el = ET.SubElement(
                graph,
                "edge",
                {"id": f"e{i}", "source": edge.source, "target": edge.target},
            )
            d2 = ET.SubElement(edge_el, "data", {"key": "d2"})
            d2.text = edge.rel
            d3 = ET.SubElement(edge_el, "data", {"key": "d3"})
            d3.text = json.dumps(edge.properties)

        return ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")

    @classmethod
    def to_maltego_mtgx(cls, store: BaseGraphStore) -> bytes:
        """
        Exports graph as a Maltego .mtgx archive containing Graph.graphml
        and Maltego entity mapping.
        """
        graphml_content = cls.to_graphml(store)

        # Maltego MTGX requires a zip archive containing Graphs/Graph1.graphml
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("Graphs/Graph1.graphml", graphml_content)
            # Add manifest
            manifest = {
                "generator": "Heimdall OSINT Engine",
                "version": "1.0",
                "nodes_count": len(store.get_nodes()),
                "edges_count": len(store.get_edges()),
            }
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        return zip_buffer.getvalue()
