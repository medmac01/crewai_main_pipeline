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
			expected_output=dedent(f"""\
			Investigation Report: IOC Analysis of {iocs}

			Introduction:
			- Briefly describe the subject of the investigation (e.g., IP address, domain, file hash).
			- Mention the reason for the investigation and the objective of the report.

			Methodology:
			- Explain the tools and methods used in the investigation (e.g., VirusTotal, sandbox analysis, malware databases).
			- Include details about specific technologies or approaches (e.g., sandbox environments, behavioral analysis).

			Findings:
			- Describe the key findings of the investigation.
			- Include details such as the nature of the files, their classification, and any associated behaviors observed during the analysis.

			Analysis & Recommendations:
			- Summarize the implications of the findings (e.g., potential malicious activities).
			- Provide actionable recommendations (e.g., further investigation steps, mitigation measures).

			Conclusion:
			- Restate the main findings and their significance.
			- Highlight the need for additional actions or monitoring if necessary.
			"""),
			agent=agent
		)

	
	