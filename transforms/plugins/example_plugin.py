"""
Example Community Plugin for Heimdall OSINT Engine.

Drop any .py file using the @heimdall_plugin decorator into this folder
and Heimdall will auto-discover and register it on startup or hot-reload.
"""

from typing import List
from heimdall.core.models import EntityType, GraphEdge
from heimdall.transforms.sdk import heimdall_plugin


@heimdall_plugin(
    name="example_subdomain_ping",
    display_name="Example Subdomain Ping",
    inputs=[EntityType.DOMAIN],
    outputs=[EntityType.DOMAIN],
    requires_api_key=False,
)
async def example_subdomain_ping(urn: str, value: str, transport, **kwargs) -> List[GraphEdge]:
    """
    Toy example plugin that synthesizes a health/status node for demonstration.
    """
    edges: List[GraphEdge] = []
    target_urn = f"Domain:status.{value.lower()}"
    edges.append(
        GraphEdge(
            source=urn,
            target=target_urn,
            target_type=EntityType.DOMAIN.value,
            rel="HAS_STATUS_HOST",
            properties={"simulated": True, "parent_domain": value},
        )
    )
    return edges
