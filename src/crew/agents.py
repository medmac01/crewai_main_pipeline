from textwrap import dedent
from crewai import Agent, LLM
from .tools.virustotal import VirusTotalTool
from .tools.misp import MISPSearchTool

class InvestigateAgents():
	def __init__(self):
		self.llm = LLM(
    	# model="ollama/hf.co/MaziyarPanahi/Mistral-Nemo-Instruct-2407-GGUF:Q4_K_M",
		model="ollama/codestral",
    	base_url="http://localhost:11434"
		)

	def misp_search(self):
		return Agent(
			role='MISP Search Specialist',
			goal='Search for Indicators of Compromise (IOCs) in MISP',
			backstory=dedent("""\
				As a MISP Search Specialist, you are skilled in searching for Indicators of Compromise (IOCs) in MISP (Malware Information Sharing Platform)."""),
			verbose=True,
			llm = self.llm,
			tools=[MISPSearchTool().search_misp],
			allow_delegation=False
		)

	def virus_total_search(self):
		return Agent(
			role='VirusTotal Search Specialist',
			goal='Search for Indicators of Compromise (IOCs) in VirusTotal',
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





	# def email_filter_agent(self):
	# 	return Agent(
	# 		role='Senior Email Analyst',
	# 		goal='Filter out non-essential emails like newsletters and promotional content',
	# 		backstory=dedent("""\
	# 			As a Senior Email Analyst, you have extensive experience in email content analysis.
	# 			You are adept at distinguishing important emails from spam, newsletters, and other
	# 			irrelevant content. Your expertise lies in identifying key patterns and markers that
	# 			signify the importance of an email."""),
	# 		verbose=True,
	# 		allow_delegation=False
	# 	)

	# def email_action_agent(self):

	# 	return Agent(
	# 		role='Email Action Specialist',
	# 		goal='Identify action-required emails and compile a list of their IDs',
	# 		backstory=dedent("""\
	# 			With a keen eye for detail and a knack for understanding context, you specialize
	# 			in identifying emails that require immediate action. Your skill set includes interpreting
	# 			the urgency and importance of an email based on its content and context."""),
	# 		tools=[
	# 			GmailGetThread(api_resource=self.gmail.api_resource),
	# 			TavilySearchResults()
	# 		],
	# 		verbose=True,
	# 		allow_delegation=False,
	# 	)

	# def email_response_writer(self):
	# 	return Agent(
	# 		role='Email Response Writer',
	# 		goal='Draft responses to action-required emails',
	# 		backstory=dedent("""\
	# 			You are a skilled writer, adept at crafting clear, concise, and effective email responses.
	# 			Your strength lies in your ability to communicate effectively, ensuring that each response is
	# 			tailored to address the specific needs and context of the email."""),
	# 		tools=[
	# 			TavilySearchResults(),
	# 			GmailGetThread(api_resource=self.gmail.api_resource),
	# 			CreateDraftTool.create_draft
	# 		],
	# 		verbose=True,
	# 		allow_delegation=False,
	# 	)