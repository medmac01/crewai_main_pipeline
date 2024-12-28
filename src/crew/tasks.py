from crewai import Task
from textwrap import dedent

class InvestigationTasks:

	def misp_search_task(self, agent, iocs):
		return Task(
			description=dedent(f"""\
				Search for Indicators of Compromise (IOCs) in MISP (Malware Information Sharing Platform).
				You are skilled in searching for Indicators of Compromise (IOCs) in MISP.
				Search for the following IOCs:
					  {iocs}
				Your final answer MUST be the results of the search.
				"""),
			expected_output="Expected output description here",
			agent=agent
		)
	
	def virus_total_search_task(self, agent, iocs):
		return Task(
			description=dedent(f"""\
				Search for Indicators of Compromise (IOCs) in VirusTotal.
				You are skilled in searching for Indicators of Compromise (e.g. IP addresses, domains, hashes) in VirusTotal.
				Search for the following IOCs:
					  {iocs}
				Your final answer MUST be the results of the search.
				"""),
			expected_output="Expected output description here",
			agent=agent
		)
	