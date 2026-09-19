"""
Tests for Heimdall Plugin SDK and Community Plugin Loader.
"""

from pathlib import Path
import tempfile
import pytest

from heimdall.core.models import EntityType, GraphEdge
from heimdall.core.plugin_loader import PluginLoader
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.registry import TransformRegistry
from heimdall.transforms.sdk import PluginDefinitionError, heimdall_plugin


@pytest.mark.asyncio
async def test_plugin_decorator_registration():
    @heimdall_plugin(
        name="test_sdk_reverse_ip",
        display_name="Test Reverse IP Plugin",
        inputs=[EntityType.IPV4],
        outputs=[EntityType.DOMAIN],
    )
    async def sample_plugin(urn: str, value: str, transport: ResilientAsyncTransport, **kwargs):
        return [
            GraphEdge(
                source=urn,
                target="Domain:reverse-found.org",
                target_type=EntityType.DOMAIN.value,
                rel="RESOLVES_TO_NAME",
            )
        ]

    # Verify registered
    transform = TransformRegistry.get("test_sdk_reverse_ip")
    assert transform is not None
    assert transform.display_name == "Test Reverse IP Plugin"
    assert EntityType.IPV4.value in transform.input_types
    assert EntityType.DOMAIN.value in transform.output_types

    # Run transform
    async with ResilientAsyncTransport() as transport:
        res = await transform.run_safe("IPv4:8.8.8.8", transport)
        assert res.status == "SUCCESS"
        assert len(res.edges) == 1
        assert res.edges[0].target == "Domain:reverse-found.org"


def test_plugin_definition_validation_errors():
    # Empty inputs must fail
    with pytest.raises(PluginDefinitionError, match="must declare at least one"):
        @heimdall_plugin(name="bad_plugin", display_name="Bad", inputs=[], outputs=[EntityType.DOMAIN])
        async def bad_func(urn, value, transport, **kwargs):
            return []

    # Non-async function must fail
    with pytest.raises(PluginDefinitionError, match="must be an async coroutine"):
        @heimdall_plugin(name="sync_plugin", display_name="Sync", inputs=[EntityType.DOMAIN], outputs=[EntityType.DOMAIN])
        def sync_func(urn, value, transport, **kwargs):
            return []


def test_plugin_loader_discovery_and_reload():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        plugin_file = p / "community_ping.py"
        plugin_file.write_text(
            """
from heimdall.transforms.sdk import heimdall_plugin
from heimdall.core.models import EntityType, GraphEdge

@heimdall_plugin(
    name="temp_discovered_plugin",
    display_name="Discovered In Test",
    inputs=[EntityType.DOMAIN],
    outputs=[EntityType.DOMAIN],
)
async def temp_discovered_plugin(urn, value, transport, **kwargs):
    return []
""",
            encoding="utf-8",
        )

        loader = PluginLoader(plugin_dir=p)
        report = loader.discover()
        assert len(report.loaded) == 1
        assert len(report.failed) == 0
        assert TransformRegistry.get("temp_discovered_plugin") is not None

        # Reload should succeed and evict cache
        reload_report = loader.reload()
        assert len(reload_report.loaded) == 1
