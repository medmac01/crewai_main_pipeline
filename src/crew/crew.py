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
		temperature=0.1,
		top_p=0.9,
		top_k=40,
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
