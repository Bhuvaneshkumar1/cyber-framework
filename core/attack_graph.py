import networkx as nx

graph=nx.DiGraph()
def add_port(port):
    graph.add_node(port)
def add_attack(source,target):
    graph.add_edge(source,target)

def show_graph():
    print("Attack Graph Nodes:")
    for node in graph.nodes:
        print(node)
    print("Attack Paths:")
    for edge in graph.edges:
        print(edge)