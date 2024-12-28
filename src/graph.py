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
		
		
		# workflow.add_node("check_new_emails", nodes.check_email)
		# workflow.add_node("wait_next_run", nodes.wait_next_run)
		# workflow.add_node("draft_responses", EmailFilterCrew().kickoff)


		# workflow.set_entry_point("check_new_emails")
		# workflow.add_conditional_edges(
		# 		"check_new_emails",
		# 		nodes.new_emails,
		# 		{
		# 			"continue": 'draft_responses',
		# 			"end": 'wait_next_run'
		# 		}
		# )
		# workflow.add_edge('draft_responses', 'wait_next_run')
		# workflow.add_edge('wait_next_run', 'check_new_emails')
		# self.app = workflow.compile()