from textwrap import dedent
from crewai import Agent, LLM
from .tools.virustotal import VirusTotalTool
from .tools.misp import MISPSearchTool

class InvestigateAgents():
	def __init__(self):
		self.llm = LLM(
    	# model="ollama/hf.co/MaziyarPanahi/Mistral-Nemo-Instruct-2407-GGUF:Q4_K_M",
		model="ollama/codestral",
		temperature=0.1,
    	base_url="http://localhost:11434"
		)

	def misp_search(self):
		return Agent(
			role='MISP Search Specialist',
			goal='Consult MISP platform for a given IOC, and retrieve relevant information',
			backstory=dedent("""\
				"You are a MISP Search Specialist skilled at finding security events related to specific IOCs in the Malware Information Sharing Platform."""),
			verbose=True,
			llm = self.llm,
			tools=[MISPSearchTool().search_misp],
			allow_delegation=False
		)

	def virus_total_search(self):
		return Agent(
			role='VirusTotal Search Specialist',
			goal='Scan a given IOC in VirusTotal, and return back the scan results',
			backstory=dedent("""\
				As a VirusTotal Search Specialist, you are skilled in searching for Indicators of Compromise (e.g. IP addresses, domains, hashes) in VirusTotal."""),
			verbose=True,
			llm = self.llm,
			tools = [VirusTotalTool().scan_related_files],
			allow_delegation=False
		)

	def draft_report(self):
		return Agent(
			role='Report Drafting Specialist',
			goal='Draft a detailed report of the investigation results',
			backstory=dedent("""\
				As a Report Drafting Specialist, you are skilled in drafting detailed reports based on the investigation results."""),
			verbose=True,
			llm = self.llm,
			allow_delegation=False
		)




