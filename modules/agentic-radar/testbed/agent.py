# Banc d’essai inerte du module agentic-radar (K7) : workflow LangGraph avec un outil shell.
# Jamais exécuté : Agentic Radar le lit (ast).
from langgraph.graph import StateGraph, END
from langchain_community.tools import ShellTool
from langchain_core.tools import tool

shell = ShellTool()

@tool
def lookup(query: str) -> str:
    """Look up a customer."""
    return query

def call_model(state):
    return state

def run_tools(state):
    return state

graph = StateGraph(dict)
graph.add_node("agent", call_model)
graph.add_node("tools", run_tools)
graph.set_entry_point("agent")
graph.add_edge("agent", "tools")
graph.add_edge("tools", END)
app = graph.compile()
