import datetime
from typing import TypedDict, Annotated, List
from langchain_core.agents import AgentAction, AgentFinish
import operator

def merge_dicts(d1, d2):
    merged = d1.copy()
    merged.update(d2)
    return merged

class InvestigationState(TypedDict):
	# input : str
	iocs : list[str]
	hypothesis: str
	history : Annotated[dict, merge_dicts]
	intermediate_steps: Annotated[list[tuple[AgentAction, str]], operator.add]



class EmailsState(TypedDict):
	checked_emails_ids: list[str]
	emails: list[dict]
	action_required_emails: dict