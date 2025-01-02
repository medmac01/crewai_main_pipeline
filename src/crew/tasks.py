from crewai import Task
from textwrap import dedent
from .tools.virustotal import VirusTotalTool, VTTool
from ..state import InvestigationState

class InvestigationTasks:

	def misp_search_task(self, agent, iocs):
		return Task(
			description=dedent(f"""\
            Your task is to search for the specified Indicators of Compromise (IOCs) in the Malware Information Sharing Platform (MISP) and retrieve security events associated to it.
            
            **Task Details:**
            - Find and retrieve relevant security events linked to the provided IOCs.
            - The IOCs to search for are:
                  {iocs}
            
            **Important Notes:**
            - Provide comprehensive results for each IOC.
            - Ensure accuracy and include all relevant details in your findings.

        """),
	        expected_output="Detailed search results for each IOC, including all relevant details from MISP.",
			agent=agent,
		)
	
	
	def virus_total_search_task(self, agent, iocs):
		# tool = VirusTotalTool().scanner
		# print(type(tool))
		# print(tool.invoke(input={"resource": "194.233.80.217",
		# 				   "scan_type": "ip"}))

		return Task(
			description=dedent(f"""\
				Your task is to scan the specified Indicators of Compromise (IOCs) in VirusTotal, and return the scan results.
            
            **Task Details:**
            - Use your knowledge of VirusTotal to analyze and retrieve details about the provided IOCs, such as IP addresses, domains, or hashes.
			- The scanner might return scan result for the IOC itself or the related files associated with the IOC.
            - The IOCs to search for are:
                  {iocs}
            
            **Important Notes:**
            - Return complete and accurate results for each IOC.
            - Highlight any significant details or patterns found in the results.
				"""),
			expected_output="Detailed search results for each IOC, including all relevant details and significant findings from VirusTotal.",
			agent=agent,
			# tools=[tool],
		)

	def draft_report_task(self, agent, iocs, hypothesis=""):

		return Task(
			description=dedent(f"""\
				Draft a detailed report of the investigation results about the following IOCs {iocs}.
				You are skilled in drafting detailed reports based on the investigation results about a given attack hypothesis.
				Use the results from previous tasks (e.g., MISP search, VirusTotal search) to draft a comprehensive report. Ensure that all relevant details from these tasks are included and analyzed.
				You should also either confirm or refute the attack hypothesis based on the investigation results.
				Your final answer MUST be a detailed report of the investigation results.
				"""),
			expected_output=dedent(f"""\
			Investigation Report: IOC Analysis of {iocs}

			Introduction:
			- Briefly describe the subject of the investigation (e.g., IP address, domain, file hash).
			- Mention the reason for the investigation and the objective of the report.

			Attack Hypothesis:
			- State the initial attack hypothesis based on the provided IOCs.
			{hypothesis}
			Methodology:
			- Explain the tools and methods used in the investigation (e.g., VirusTotal, MISP, sandbox analysis, malware databases).
			- Include details about specific technologies or approaches (e.g., sandbox environments, behavioral analysis).

			Findings:
			- Describe the key findings of the investigation for each of the tools used.
			- Include details such as the nature of the files, their classification, and any associated behaviors observed during the analysis.

			Analysis & Recommendations:
			- Summarize the implications of the findings (e.g., potential malicious activities).

			Conclusion:
			- Restate the main findings and their significance.
			"""),
			agent=agent
		)

	
	