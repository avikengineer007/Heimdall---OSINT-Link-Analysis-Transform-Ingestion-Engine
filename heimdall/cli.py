"""
Interactive Rich Terminal CLI for Heimdall OSINT Engine.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Optional
import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.tree import Tree

from heimdall import __version__
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.graph.cypher_engine import CypherEngine
from heimdall.graph.exporters import GraphExporter
from heimdall.graph.memory_store import MemoryGraphStore
from heimdall.pipeline.orchestrator import PipelineOrchestrator
from heimdall.transforms.registry import TransformRegistry

console = Console(safe_box=True)


@click.group()
@click.version_option(version=__version__, prog_name="Heimdall OSINT Engine")
def main():
    """Heimdall: Modular OSINT Link-Analysis Transform & Ingestion Engine."""
    pass


@main.group()
def transforms():
    """Manage and inspect OSINT transforms."""
    pass


@transforms.command(name="list")
def list_transforms_cmd():
    """Lists all available transforms with supported input/output entity types."""
    table = Table(title="Heimdall Registered OSINT Transforms", border_style="cyan", safe_box=True)
    table.add_column("Transform Name", style="bold green")
    table.add_column("Input Types", style="yellow")
    table.add_column("Output Types", style="magenta")
    table.add_column("Key Required", justify="center")
    table.add_column("Description")

    for t in TransformRegistry.list_transforms():
        table.add_row(
            t["name"],
            ", ".join(t["input_types"]),
            ", ".join(t["output_types"]),
            "Yes" if t["requires_api_key"] else "No",
            t["description"],
        )

    console.print(table)


@transforms.command(name="run")
@click.argument("name")
@click.option("--input", "entity_urn", required=True, help="Input entity URN (e.g. Domain:example.com)")
@click.option("--key", "api_key", default=None, help="Optional API key for authenticated transforms")
def run_transform_cmd(name: str, entity_urn: str, api_key: Optional[str]):
    """Executes a single transform against an entity URN."""
    transform = TransformRegistry.get(name)
    if not transform:
        console.print(f"[bold red]Error:[/bold red] Transform '{name}' not found.")
        sys.exit(1)

    async def _run():
        async with ResilientAsyncTransport() as transport:
            kwargs = {}
            if api_key:
                kwargs["shodan_api_key"] = api_key
            result = await transform.run_safe(entity_urn, transport, **kwargs)
            return result

    console.print(f"[bold cyan]Executing transform '{name}' on '{entity_urn}'...[/bold cyan]")
    result = asyncio.run(_run())

    if result.status == "FAILED":
        console.print(f"[bold red]Transform Failed:[/bold red] {result.error_message}")
        sys.exit(1)

    console.print(
        Panel(
            f"[bold green]Transform Success[/bold green] in {result.duration_ms} ms\n"
            f"Discovered {len(result.edges)} new relationships.",
            title=f"Result: {name}",
            safe_box=True,
        )
    )

    if result.edges:
        table = Table(border_style="green", safe_box=True)
        table.add_column("Source", style="cyan")
        table.add_column("Relationship", style="bold yellow")
        table.add_column("Target", style="magenta")
        table.add_column("Properties", style="dim")

        for e in result.edges:
            table.add_row(e.source, e.rel, e.target, json.dumps(e.properties))

        console.print(table)


@main.command()
@click.option("--seed", required=True, help="Initial target (e.g. example.com, 1.1.1.1)")
@click.option("--depth", default=2, type=int, help="Max recursion depth (default: 2)")
@click.option("--export", "export_path", default=None, help="Path to save output (json, graphml, mtgx)")
@click.option("--cypher", is_flag=True, help="Print Cypher MERGE batch queries to console")
def investigate(seed: str, depth: int, export_path: Optional[str], cypher: bool):
    """Executes a multi-hop link analysis crawl starting from a seed indicator."""
    console.print(
        Panel(
            f"[bold white]Target Seed:[/bold white] [cyan]{seed}[/cyan]\n"
            f"[bold white]Max Depth:[/bold white] [yellow]{depth}[/yellow]\n"
            f"[bold white]Active Transforms:[/bold white] [green]{len(TransformRegistry.list_transforms())}[/green]",
            title="[bold red]Heimdall Link Analysis Crawl[/bold red]",
            border_style="red",
            safe_box=True,
        )
    )

    store = MemoryGraphStore()
    discovered_edges = []

    def on_event(event: dict):
        etype = event.get("type")
        edata = event.get("data", {})
        if etype == "EDGE_DISCOVERED":
            discovered_edges.append(edata)
            console.print(
                f"  [cyan]{edata.get('source')}[/cyan] "
                f"-[bold yellow]{edata.get('rel')}[/bold yellow]-> "
                f"[magenta]{edata.get('target')}[/magenta]"
            )
        elif etype == "DEPTH_STARTED":
            console.print(f"\n[bold blue]--- Depth Hop {edata.get('depth')} ---[/bold blue]")

    orchestrator = PipelineOrchestrator(graph_store=store, event_callback=on_event)

    console.print("[green]Crawling and enriching target graph...[/green]")
    session = asyncio.run(orchestrator.run_investigation(seed=seed, max_depth=depth))

    stats = store.get_stats()
    console.print(
        Panel(
            f"[bold green]Crawl Completed Successfully[/bold green]\n"
            f"Total Nodes: [bold cyan]{stats['total_nodes']}[/bold cyan]\n"
            f"Total Relationships: [bold magenta]{stats['total_edges']}[/bold magenta]\n"
            f"Graph Density: [dim]{stats['density']}[/dim]\n"
            f"Node Types Breakdown: {json.dumps(stats['node_types'], indent=2)}",
            title="Investigation Metrics",
            border_style="green",
        )
    )

    if cypher and store.get_edges():
        from rich.markup import escape
        console.print("\n[bold yellow]Generated Parameterized Cypher Merge Queries:[/bold yellow]")
        stmts = CypherEngine.build_native_merges(store.get_edges()[:5])
        for s in stmts:
            console.print(f"[dim]{escape(s['query'])}[/dim]")
            console.print(f"Params: {json.dumps(s['params'])}\n")

    if export_path:
        path_lower = export_path.lower()
        if path_lower.endswith(".json"):
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(GraphExporter.to_json(store))
            console.print(f"[bold green]Exported JSON graph to:[/bold green] {export_path}")
        elif path_lower.endswith(".graphml"):
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(GraphExporter.to_graphml(store))
            console.print(f"[bold green]Exported GraphML to:[/bold green] {export_path}")
        elif path_lower.endswith(".mtgx"):
            with open(export_path, "wb") as f:
                f.write(GraphExporter.to_maltego_mtgx(store))
            console.print(f"[bold green]Exported Maltego MTGX to:[/bold green] {export_path}")
        else:
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(GraphExporter.to_json(store))
            console.print(f"[bold green]Exported graph to:[/bold green] {export_path}")


@main.command()
@click.option("--host", default="127.0.0.1", help="Bind host")
@click.option("--port", default=8000, type=int, help="Bind port")
def serve(host: str, port: int):
    """Starts the Heimdall FastAPI server."""
    import uvicorn
    console.print(f"[bold green]Starting Heimdall API Server at http://{host}:{port}[/bold green]")
    uvicorn.run("heimdall.api.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
