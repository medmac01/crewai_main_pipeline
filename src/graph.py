from dotenv import load_dotenv
load_dotenv()

from langgraph.graph import StateGraph

from .state import InvestigationState
from .nodes import Nodes
from .crew.crew import Investigator

class WorkFlow():
	def __init__(self):
		nodes = Nodes()
		workflow = StateGraph(InvestigationState)


		workflow.add_node("pull_alert", nodes.pull_alert)
		workflow.add_node("get_iocs", nodes.get_iocs)
		workflow.add_node("investigate", Investigator().kickoff)
		workflow.add_node("summarize", nodes.summarize)
		
		workflow.set_entry_point("pull_alert")
		workflow.add_edge("pull_alert", "get_iocs")
		workflow.add_edge("get_iocs", "investigate")
		workflow.add_edge("investigate", "summarize")

		self.app = workflow.compile()