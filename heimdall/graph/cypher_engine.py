"""
Cypher Query Compiler for Idempotent Neo4j Mutations.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List
from heimdall.core.models import GraphEdge


class CypherEngine:
    """Compiles GraphEdge contracts into atomic, parameterized Cypher statements."""

    @staticmethod
    def schema_indexes() -> List[str]:
        """Returns standard indexing and constraint queries for Neo4j."""
        return [
            "CREATE CONSTRAINT entity_urn_unique IF NOT EXISTS FOR (e:Entity) REQUIRE e.urn IS UNIQUE;",
            "CREATE INDEX entity_type_idx IF NOT EXISTS FOR (e:Entity) ON (e.type);",
            "CREATE INDEX entity_val_idx IF NOT EXISTS FOR (e:Entity) ON (e.value);",
        ]

    @staticmethod
    def build_batch_unwind(edges: List[GraphEdge]) -> Dict[str, Any]:
        """
        Builds a single parameterized batch query utilizing UNWIND.
        This provides high throughput and prevents deadlocks.
        """
        query = """
        UNWIND $batch AS row
        MERGE (s:Entity {urn: row.source})
        ON CREATE SET s.type = row.source_type, s.value = row.source_value
        MERGE (t:Entity {urn: row.target})
        ON CREATE SET t.type = row.target_type, t.value = row.target_value
        WITH s, t, row
        CALL apoc.create.relationship(s, row.rel, row.properties, t) YIELD rel
        RETURN count(rel) AS relations_merged
        """
        payload = []
        for e in edges:
            src_type, src_val = e.source.split(":", 1)
            tgt_type, tgt_val = e.target.split(":", 1)
            payload.append({
                "source": e.source,
                "source_type": src_type,
                "source_value": src_val,
                "target": e.target,
                "target_type": e.target_type,
                "target_value": tgt_val,
                "rel": e.rel,
                "properties": e.properties,
            })
        return {
            "query": re.sub(r"\s+", " ", query).strip(),
            "params": {"batch": payload},
        }

    @staticmethod
    def build_native_merges(edges: List[GraphEdge]) -> List[Dict[str, Any]]:
        """
        Generates individual native Cypher MERGE queries that don't depend on APOC plugins.
        """
        statements = []
        for e in edges:
            src_type, src_val = e.source.split(":", 1)
            tgt_type, tgt_val = e.target.split(":", 1)
            # Sanitize labels and rel name
            clean_src_label = re.sub(r"[^a-zA-Z0-9_]", "_", src_type)
            clean_tgt_label = re.sub(r"[^a-zA-Z0-9_]", "_", tgt_type)
            clean_rel = re.sub(r"[^a-zA-Z0-9_]", "_", e.rel)

            query = f"""
            MERGE (s:`{clean_src_label}` {{urn: $src_urn}})
            ON CREATE SET s.value = $src_val
            MERGE (t:`{clean_tgt_label}` {{urn: $tgt_urn}})
            ON CREATE SET t.value = $tgt_val
            MERGE (s)-[r:`{clean_rel}`]->(t)
            SET r += $props
            """
            statements.append({
                "query": re.sub(r"\s+", " ", query).strip(),
                "params": {
                    "src_urn": e.source,
                    "src_val": src_val,
                    "tgt_urn": e.target,
                    "tgt_val": tgt_val,
                    "props": e.properties,
                },
            })
        return statements
