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


@main.command(name="attack-path")
@click.option("--source", required=True, help="Entrypoint node URN (e.g. Domain:example.com or IPv4:1.2.3.4)")
@click.option("--target", default=None, help="Target node URN. If omitted, automatically finds critical targets.")
@click.option("--depth", default=2, type=int, help="Investigation crawl depth if running fresh investigation")
@click.option("--graph-file", default=None, help="Load existing JSON graph export instead of crawling")
@click.option("--unweighted", is_flag=True, default=False, help="Use hop count (BFS) instead of least resistance Dijkstra")
def attack_path_cmd(source: str, target: Optional[str], depth: int, graph_file: Optional[str], unweighted: bool):
    """Computes the shortest path of attack and critical attack vectors."""
    store = MemoryGraphStore()

    if graph_file:
        try:
            with open(graph_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            from heimdall.core.models import GraphEdge, GraphNode
            for n_data in data.get("nodes", []):
                urn = n_data.get("urn") or n_data.get("id")
                e_type = n_data.get("entity_type") or n_data.get("type") or (urn.split(":", 1)[0] if ":" in urn else "Unknown")
                val = n_data.get("value") or (urn.split(":", 1)[1] if ":" in urn else urn)
                props = n_data.get("properties", {})
                t_score = n_data.get("threat_score", props.get("threat_score", 0.0))
                store.add_node(GraphNode(
                    urn=urn,
                    entity_type=e_type,
                    value=val,
                    properties=props,
                    threat_score=t_score,
                ))
            for e_data in (data.get("edges") or data.get("links", [])):
                s = e_data.get("source") or e_data.get("from")
                t = e_data.get("target") or e_data.get("to")
                t_type = e_data.get("target_type") or (t.split(":", 1)[0] if ":" in t else "Unknown")
                store.add_edge(GraphEdge(
                    source=s,
                    target=t,
                    rel=e_data.get("rel") or e_data.get("label", "CONNECTED_TO"),
                    target_type=t_type,
                    properties=e_data.get("properties", {}),
                ))
            console.print(f"[bold green]Loaded graph with {len(store.get_nodes())} nodes from {graph_file}[/bold green]")
        except Exception as exc:
            console.print(f"[bold red]Failed to load graph file: {exc}[/bold red]")
            sys.exit(1)
    else:
        # Crawl to discover topology
        async def _crawl():
            transport = ResilientAsyncTransport()
            orch = PipelineOrchestrator(graph_store=store, transport=transport)
            try:
                await orch.run_investigation(seed=source, max_depth=depth)
            finally:
                await transport.close()

        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold cyan]Crawling attack surface from {task.fields[seed]}..."),
            console=console,
        ) as progress:
            progress.add_task("crawl", seed=source)
            asyncio.run(_crawl())

    paths = store.analyze_attack_path(
        source_urn=source,
        target_urn=target,
        weighted=not unweighted,
        top_k=5,
    )

    if not paths:
        console.print(f"[bold yellow]No viable attack path discovered from {source}[/bold yellow]")
        if target:
            console.print(f"[dim]No connected graph path found between {source} and {target}[/dim]")
        return

    console.print(f"\n[bold red][!] Discovered {len(paths)} Shortest Attack Vector(s)[/bold red]\n")

    for idx, p in enumerate(paths, 1):
        tree = Tree(f"[bold white]Vector #{idx}:[/bold white] [bold red]{p['source_urn']}[/bold red] -> [bold red]{p['target_urn']}[/bold red]")
        tree.add(f"[dim]Hop Count:[/dim] [cyan]{p['hop_count']}[/cyan] | [dim]Resistance:[/dim] [yellow]{p['total_resistance']}[/yellow] | [dim]Avg Threat Score:[/dim] [red]{p['average_threat_score']}[/red]")
        
        hops_branch = tree.add("[bold]Lateral Hops & Pivots:[/bold]")
        for hop in p.get("hops", []):
            hops_branch.add(
                f"[yellow]{hop['source_urn']}[/yellow] ---([bold magenta]{hop['relation']}[/bold magenta])---> "
                f"[bold cyan]{hop['target_urn']}[/bold cyan] [dim]({hop['target_type']}, risk: {hop['target_threat_score']})[/dim]"
            )
        
        console.print(tree)
        console.print(f"[dim italic]{p.get('narrative', '')}[/dim italic]\n")

        if p.get("chokepoints"):
            console.print(
                Panel(
                    f"[bold yellow]Key Defensive Chokepoints to Sever:[/bold yellow] "
                    f"{', '.join(p['chokepoints'])}\n"
                    f"[dim]Remediating or isolating these intermediary nodes blocks this attack path.[/dim]",
                    title="Defensive Chokepoint Recommendation",
                    border_style="yellow",
                )
            )



def _load_graph_store_from_file(graph_file: str) -> MemoryGraphStore:
    """Helper to parse a JSON export into a MemoryGraphStore."""
    store = MemoryGraphStore()
    with open(graph_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    from heimdall.core.models import GraphEdge, GraphNode
    for n_data in data.get("nodes", []):
        urn = n_data.get("urn") or n_data.get("id")
        e_type = n_data.get("entity_type") or n_data.get("type") or (urn.split(":", 1)[0] if ":" in urn else "Unknown")
        val = n_data.get("value") or (urn.split(":", 1)[1] if ":" in urn else urn)
        props = n_data.get("properties", {})
        t_score = n_data.get("threat_score", props.get("threat_score", 0.0))
        store.add_node(GraphNode(
            urn=urn,
            entity_type=e_type,
            value=val,
            properties=props,
            threat_score=t_score,
        ))
    for e_data in (data.get("edges") or data.get("links", [])):
        s = e_data.get("source") or e_data.get("from")
        t = e_data.get("target") or e_data.get("to")
        t_type = e_data.get("target_type") or (t.split(":", 1)[0] if ":" in t else "Unknown")
        store.add_edge(GraphEdge(
            source=s,
            target=t,
            rel=e_data.get("rel") or e_data.get("label", "CONNECTED_TO"),
            target_type=t_type,
            properties=e_data.get("properties", {}),
        ))
    return store


@main.command(name="cluster")
@click.option("--graph", "graph_file", required=True, help="Path to graph JSON export file")
def cluster_cmd(graph_file: str):
    """Detects infrastructure communities and modularity clusters from a graph export."""
    from heimdall.graph.clustering import GraphClusterEngine
    store = _load_graph_store_from_file(graph_file)
    engine = GraphClusterEngine()
    clusters = engine.detect_communities(store.get_nodes(), store.get_edges())

    table = Table(title=f"Discovered Graph Communities ({len(clusters)} clusters)", border_style="cyan", safe_box=True)
    table.add_column("ID", justify="center")
    table.add_column("Semantic Label", style="bold magenta")
    table.add_column("Density", justify="center")
    table.add_column("Nodes", justify="center")
    table.add_column("Avg Risk", justify="center", style="bold red")
    table.add_column("Central Hub Node", style="cyan")

    for c in clusters:
        table.add_row(
            str(c["cluster_id"]),
            c["label"],
            str(c["density"]),
            str(c["node_count"]),
            str(c["avg_threat_score"]),
            c["hub_node"],
        )

    console.print(table)


@main.command(name="report")
@click.option("--graph", "graph_file", required=True, help="Path to graph JSON export file")
@click.option("--format", "fmt", default="markdown", type=click.Choice(["markdown", "html"]), help="Output format")
@click.option("--out", "output_file", default=None, help="Output file path (default: stdout)")
def report_cmd(graph_file: str, fmt: str, output_file: Optional[str]):
    """Generates an executive CISO threat intelligence report from graph telemetry."""
    from heimdall.graph.reports import ExecutiveReportGenerator
    store = _load_graph_store_from_file(graph_file)
    gen = ExecutiveReportGenerator()
    attack_paths = store.analyze_attack_path(top_k=5)
    target = graph_file.split("/")[-1].split("\\")[-1]

    if fmt == "html":
        content = gen.generate_html(target, store.get_nodes(), store.get_edges(), attack_paths)
    else:
        content = gen.generate_markdown(target, store.get_nodes(), store.get_edges(), attack_paths)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"[bold green][+] Executive {fmt.upper()} report saved to {output_file}[/bold green]")
    else:
        print(content)


@main.command(name="copilot")
@click.option("--graph", "graph_file", required=True, help="Path to graph JSON export file")
@click.argument("query")
def copilot_cmd(graph_file: str, query: str):
    """Executes a natural language query against graph assets using the Threat Copilot."""
    from heimdall.core.copilot import ThreatCopilot
    store = _load_graph_store_from_file(graph_file)
    copilot = ThreatCopilot()
    res = copilot.parse_query(query, store.get_nodes(), store.get_edges())

    console.print(Panel(
        f"[bold cyan]Query:[/bold cyan] {query}\n"
        f"[bold yellow]Interpretation:[/bold yellow] {res['interpretation']}\n"
        f"[bold green]Answer:[/bold green] {res['answer']}",
        title="[bold]Heimdall Threat Copilot[/bold]",
        border_style="cyan",
        safe_box=True,
    ))

    if res["matched_nodes"]:
        table = Table(title=f"Matching Assets ({res['matched_count']})", border_style="green", safe_box=True)
        table.add_column("Asset URN", style="bold cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Risk Score", justify="center")

        urn_set = set(res["matched_nodes"])
        for n in store.get_nodes():
            if n.urn in urn_set:
                score = str(n.properties.get("threat_score", "0"))
                table.add_row(n.urn, n.entity_type, score)

        console.print(table)


@main.command(name="takeover")
@click.argument("domain")
def takeover_cmd(domain: str):
    """Scans a domain for dangling DNS CNAME records and subdomain takeovers."""
    from heimdall.transforms.takeover import SubdomainTakeoverTransform
    transform = SubdomainTakeoverTransform()

    async def _run():
        async with ResilientAsyncTransport() as transport:
            urn = f"Domain:{domain}" if not domain.startswith("Domain:") and not domain.startswith("Subdomain:") else domain
            return await transform.run_safe(urn, transport)

    console.print(f"[bold cyan][*] Probing {domain} for dangling CNAME takeover vulnerabilities...[/bold cyan]")
    res = asyncio.run(_run())
    if not res.edges:
        console.print(f"[bold green][+] No dangling DNS takeover vulnerabilities detected for {domain}.[/bold green]")
    else:
        console.print(f"[bold red][!] Detected {len(res.edges)} potential takeover vulnerabilities![/bold red]")
        for e in res.edges:
            console.print(f"  [bold red]->[/bold red] [yellow]{e.source}[/yellow] ({e.rel}) [red]{e.target}[/red]")
            if "reason" in e.properties:
                console.print(f"     [dim]{e.properties['reason']}[/dim]")


@main.command(name="cloud-buckets")
@click.argument("target")
def cloud_buckets_cmd(target: str):
    """Probes for open and protected cloud storage buckets (AWS S3, Azure Blob, GCS)."""
    from heimdall.transforms.cloud_buckets import CloudBucketHunterTransform
    transform = CloudBucketHunterTransform()

    async def _run():
        async with ResilientAsyncTransport() as transport:
            urn = f"Domain:{target}" if ":" not in target else target
            return await transform.run_safe(urn, transport)

    console.print(f"[bold cyan][*] Hunting public cloud buckets for target '{target}'...[/bold cyan]")
    res = asyncio.run(_run())
    if not res.edges:
        console.print(f"[bold yellow][*] No public buckets uncovered with probed permutations.[/bold yellow]")
    else:
        table = Table(title=f"Discovered Cloud Storage Buckets ({len(res.edges)})", border_style="cyan", safe_box=True)
        table.add_column("Bucket URL", style="bold cyan")
        table.add_column("Cloud Provider", style="yellow")
        table.add_column("Status", style="bold red")
        table.add_column("Risk Score", justify="center")

        for e in res.edges:
            table.add_row(
                e.target.replace("CloudBucket:", ""),
                e.properties.get("provider", "Unknown"),
                e.properties.get("status", "Unknown"),
                str(e.properties.get("threat_score", "0")),
            )
        console.print(table)


@main.command()
@click.option("--host", default="127.0.0.1", help="Bind host")
@click.option("--port", default=None, type=int, help="Bind port")
def serve(host: str, port: Optional[int]):
    """Starts the Heimdall FastAPI server."""
    import os
    import uvicorn
    effective_port = port if port is not None else int(os.environ.get("PORT", 8000))
    console.print(f"[bold green]Starting Heimdall API Server at http://{host}:{effective_port}[/bold green]")
    uvicorn.run("heimdall.api.app:app", host=host, port=effective_port, reload=False)


if __name__ == "__main__":
    main()


