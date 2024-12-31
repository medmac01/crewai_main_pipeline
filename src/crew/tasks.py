from crewai import Task
from textwrap import dedent
from .tools.virustotal import VirusTotalTool, VTTool

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
			expected_output="Explain the search results regarding the input IOCs. Make sure to include all relevant details.",
			agent=agent,
		)
	
	def virus_total_search_task(self, agent, iocs):
		# tool = VirusTotalTool().scanner
		# print(type(tool))
		# print(tool.invoke(input={"resource": "194.233.80.217",
		# 				   "scan_type": "ip"}))

		return Task(
			description=dedent(f"""\
				Search for Indicators of Compromise (IOCs) in VirusTotal.
				You are skilled in searching for Indicators of Compromise (e.g. IP addresses, domains, hashes) in VirusTotal.
				Search for the following IOCs:
					  {iocs}
				Your final answer MUST be the results of the search.
				"""),
			expected_output="Expected output description here",
			agent=agent,
			# tools=[tool],
		)

	def draft_report_task(self, agent, iocs):

		return Task(
			description=dedent(f"""\
				Draft a detailed report of the investigation results about the following IOCs {iocs}.
				You are skilled in drafting detailed reports based on the investigation results.
				Use past task results to draft a comprehensive report.
				Your final answer MUST be a detailed report of the investigation results.
				"""),
			expected_output="Comprehensive report of the investigation results, detailing and analysing each tasks's results;",
			agent=agent
		)

	
	