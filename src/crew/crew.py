from crewai import Crew, LLM, Process

from .agents import InvestigateAgents
from .tasks import InvestigationTasks

class Investigator():
	def __init__(self):
		agents = InvestigateAgents()
		self.misp_agent = agents.misp_search()
		self.virus_total_agent = agents.virus_total_search()
		self.report_agent = agents.draft_report()


	def kickoff(self, state):
		print("### Investigation started")
		tasks = InvestigationTasks()
		llm = LLM(
    	# model="ollama/hf.co/MaziyarPanahi/Mistral-Nemo-Instruct-2407-GGUF:Q4_K_M",
    	model="ollama/mistral",
    	base_url="http://localhost:11434"
		)
		crew = Crew(
			agents=[self.misp_agent, self.virus_total_agent],
			tasks=[
				tasks.misp_search_task(self.misp_agent, state['iocs']),
				tasks.virus_total_search_task(self.virus_total_agent, state['iocs']),
				tasks.draft_report_task(self.report_agent, state['iocs'], state['hypothesis'])

			],
			name="Investigation process",
			description="Conduct a threat hunting investigation on the provided IOCs using each of the tools available. Then at the end, try to align the tools results with the hypothesis and draft a detailed report of the investigation results based on the",
			# description="Investigate the provided IOCs using available tools MISP and VirusTotal, then draft a detailed report of the investigation results, which would determine if the established hypothesis is correct or not.",
			verbose=True,
			manager_llm=llm,
			output_log_file="investigation_output.log",
			process = Process.sequential,
			# planning = True,
			# planning_llm = llm,
			cache = False
		)
		result = crew.kickoff()
		return {**state, "history": result}

	# def _format_emails(self, emails):
	# 	emails_string = []
	# 	for email in emails:
	# 		print(email)
	# 		arr = [
	# 			f"ID: {email['id']}",
	# 			f"- Thread ID: {email['threadId']}",
	# 			f"- Snippet: {email['snippet']}",
	# 			f"- From: {email['sender']}",
	# 			f"--------"
	# 		]
	# 		emails_string.append("\n".join(arr))
	# 	return "\n".join(emails_string)
# 




# class EmailFilterCrew():
# 	def __init__(self):
# 		agents = EmailFilterAgents()
# 		self.filter_agent = agents.email_filter_agent()
# 		self.action_agent = agents.email_action_agent()
# 		self.writer_agent = agents.email_response_writer()

# 	def kickoff(self, state):
# 		print("### Filtering emails")
# 		tasks = EmailFilterTasks()
# 		crew = Crew(
# 			agents=[self.filter_agent, self.action_agent, self.writer_agent],
# 			tasks=[
# 				tasks.filter_emails_task(self.filter_agent, self._format_emails(state['emails'])),
# 				tasks.action_required_emails_task(self.action_agent),
# 				tasks.draft_responses_task(self.writer_agent)
# 			],
# 			verbose=True
# 		)
# 		result = crew.kickoff()
# 		return {**state, "action_required_emails": result}

# 	def _format_emails(self, emails):
# 		emails_string = []
# 		for email in emails:
# 			print(email)
# 			arr = [
# 				f"ID: {email['id']}",
# 				f"- Thread ID: {email['threadId']}",
# 				f"- Snippet: {email['snippet']}",
# 				f"- From: {email['sender']}",
# 				f"--------"
# 			]
# 			emails_string.append("\n".join(arr))
# 		return "\n".join(emails_string)