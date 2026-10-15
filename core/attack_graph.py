try:
    from rich.console import Console
    from rich.tree import Tree
    from rich.table import Table
    _HAS_RICH = True
    console = Console()
except ImportError:
    _HAS_RICH = False
    console = None

try:
    import networkx as nx
    graph = nx.DiGraph()
except ImportError:
    class SimpleDiGraph:
        """Lightweight pure-Python fallback for directed graph modeling."""
        def __init__(self):
            self.nodes = set()
            self.edges = set()

        def add_node(self, node):
            self.nodes.add(node)

        def add_edge(self, source, target):
            self.nodes.add(source)
            self.nodes.add(target)
            self.edges.add((source, target))

        def clear(self):
            self.nodes.clear()
            self.edges.clear()

    graph = SimpleDiGraph()


def add_target(target: str):
    """Add a verified target node to the graph."""
    if target:
        graph.add_node(f"Target: {target}")


def add_port(port, target: str | None = None, service: str | None = None):
    """
    Record an empirically discovered port and connect it to its target host.
    Ensures graph relationships represent verified findings without fabrication.
    """
    port_label = f"Port: {port}" + (f" ({service})" if service else "")
    graph.add_node(port_label)

    if target:
        target_label = f"Target: {target}"
        graph.add_node(target_label)
        graph.add_edge(target_label, port_label)


def add_finding(source_node: str, finding_type: str, details: str = ""):
    """Connect a verified security observation to its source node."""
    finding_label = f"Observation: [{finding_type}] {details}".strip()
    graph.add_node(finding_label)
    graph.add_edge(source_node, finding_label)


def add_attack(source, target):
    """Record an attack relationship or path between verified assets."""
    graph.add_edge(str(source), str(target))


def clear_graph():
    """Reset graph state."""
    graph.clear()


def get_graph_data() -> dict:
    """Return serialized graph nodes and edges."""
    return {
        "nodes": list(graph.nodes),
        "edges": [list(e) for e in graph.edges]
    }


def show_graph():
    """Display the attack graph visually in the console using Rich or plain text fallback."""
    if not graph.nodes:
        if _HAS_RICH and console is not None:
            console.print("[yellow]Attack Graph is currently empty. Run a scan to map targets and ports.[/yellow]")
        else:
            print("Attack Graph is currently empty. Run a scan to map targets and ports.")
        return

    if _HAS_RICH and console is not None:
        tree = Tree("[bold cyan]Attack Surface & Path Graph[/bold cyan]")

        # Identify root targets
        target_nodes = [n for n in graph.nodes if str(n).startswith("Target:")]

        if target_nodes:
            for t in sorted(target_nodes, key=str):
                branch = tree.add(f"[bold green]{t}[/bold green]")
                # Find direct edges from this target
                connected_edges = [edge for edge in graph.edges if edge[0] == t]
                for _, child in connected_edges:
                    sub_branch = branch.add(f"[cyan]{child}[/cyan]")
                    # Secondary edges
                    sec_edges = [edge for edge in graph.edges if edge[0] == child]
                    for _, leaf in sec_edges:
                        sub_branch.add(f"[yellow]{leaf}[/yellow]")
        else:
            for node in sorted(graph.nodes, key=str):
                tree.add(f"[green]{node}[/green]")

        console.print(tree)

        if graph.edges:
            table = Table(title="Attack Path Edges")
            table.add_column("Origin Node", style="cyan")
            table.add_column("Relationship", style="magenta")
            table.add_column("Destination Node", style="green")

            for u, v in sorted(graph.edges, key=lambda x: (str(x[0]), str(x[1]))):
                table.add_row(str(u), "-->", str(v))

            console.print(table)
    else:
        print("=== Attack Surface & Path Graph ===")
        for node in sorted(graph.nodes, key=str):
            print(f"Node: {node}")
        if graph.edges:
            print("Edges:")
            for u, v in sorted(graph.edges, key=lambda x: (str(x[0]), str(x[1]))):
                print(f"  {u} --> {v}")
        print("===================================")