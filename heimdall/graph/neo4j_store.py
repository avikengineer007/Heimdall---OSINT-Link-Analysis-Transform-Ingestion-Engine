"""
Neo4j Graph Store implementation using the official async driver.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from heimdall.core.models import GraphEdge, GraphNode
from heimdall.graph.base import BaseGraphStore
from heimdall.graph.cypher_engine import CypherEngine

logger = logging.getLogger("heimdall.graph.neo4j")


class Neo4jGraphStore(BaseGraphStore):
    """
    Asynchronous Neo4j Store executing atomic Cypher queries.
    Gracefully degrades if the neo4j library or server is unavailable.
    """

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "password",
        database: str = "neo4j",
    ):
        self.uri = uri
        self.user = user
        self.password = password
        self.database = database
        self._driver = None

    async def connect(self) -> bool:
        """Initializes async driver connection and applies index constraints."""
        try:
            import neo4j
            self._driver = neo4j.AsyncGraphDatabase.driver(
                self.uri, auth=(self.user, self.password)
            )
            # Verify connectivity
            await self._driver.verify_connectivity()
            logger.info(f"Connected to Neo4j instance at {self.uri}")

            # Apply schema constraints
            async with self._driver.session(database=self.database) as session:
                for query in CypherEngine.schema_indexes():
                    try:
                        await session.run(query)
                    except Exception as exc:
                        logger.debug(f"Index setup notice: {exc}")
            return True
        except ImportError:
            logger.warning("neo4j package is not installed. Neo4j persistence disabled.")
            return False
        except Exception as exc:
            logger.warning(f"Failed to connect to Neo4j at {self.uri}: {exc}")
            return False

    async def close(self) -> None:
        if self._driver:
            await self._driver.close()

    def add_node(self, node: GraphNode) -> None:
        # Implemented via batch Cypher ingest
        pass

    def add_edge(self, edge: GraphEdge) -> bool:
        # Handled in async batch
        return True

    def add_edges(self, edges: List[GraphEdge]) -> int:
        return len(edges)

    async def ingest_edges_async(self, edges: List[GraphEdge]) -> int:
        """Asynchronously writes a batch of edges into Neo4j."""
        if not self._driver or not edges:
            return 0

        statements = CypherEngine.build_native_merges(edges)
        count = 0
        try:
            async with self._driver.session(database=self.database) as session:
                for stmt in statements:
                    await session.run(stmt["query"], stmt["params"])
                    count += 1
        except Exception as exc:
            logger.error(f"Neo4j batch ingestion error: {exc}")
        return count

    def get_neighbors(self, urn: str, direction: str = "both") -> List[str]:
        return []

    def get_edges(self) -> List[GraphEdge]:
        return []

    def get_nodes(self) -> List[GraphNode]:
        return []

    def get_stats(self) -> Dict[str, Any]:
        return {"backend": "neo4j", "uri": self.uri}
