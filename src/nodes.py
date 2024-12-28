import os
import time
from textwrap import dedent

from langchain_community.agent_toolkits import GmailToolkit
from langchain_community.tools.gmail.search import GmailSearch

class Nodes():
	def __init__(self):
		pass

	def pull_alert(self, state):
		state['iocs'] = ["172.32.0.2"]
		return {
			**state,
			"input" : dedent("""event_type: flow, proto: UDP, app_proto: dhcp, flow_pkts_toserver: 1, flow_pkts_toclient: 1, flow_bytes_toserver: 342, flow_bytes_toclient: 371, flow_age: 0, flow_state: established, flow_reason: timeout ; pcap_cnt: 35923, event_type: dhcp, proto: UDP, dhcp_type: request, dhcp_id: 2032925257, dhcp_client_mac: 02:62:a9:6f:87:18, dhcp_assigned_ip: 0.0.0.0, dhcp_client_ip: 172.31.69.18, dhcp_dhcp_type: request, dhcp_hostname: ip-172-31-69-18, dhcp_params_0: subnet_mask, dhcp_params_1: router, dhcp_params_2: domain, dhcp_params_3: dns_server, dhcp_params_4: ntp_server ; pcap_cnt: 35924, event_type: dhcp, proto: UDP, dhcp_type: reply, dhcp_id: 2032925257, dhcp_client_mac: 02:62:a9:6f:87:18, dhcp_assigned_ip: 172.31.69.18, dhcp_client_ip: 172.31.69.18, dhcp_relay_ip: 0.0.0.0, dhcp_next_server_ip: 0.0.0.0, dhcp_dhcp_type: ack, dhcp_lease_time: 3600, dhcp_subnet_mask: 255.255.255.224, dhcp_routers_0: 172.31.69.1, dhcp_dns_servers_0: 172.31.0.2, dhcp_hostname: ip-172-31-69-18',
       'event_type: flow, proto: TCP, app_proto: http, flow_pkts_toserver: 5, flow_pkts_toclient: 4, flow_bytes_toserver: 302, flow_bytes_toclient: 1192, flow_age: 97, flow_state: closed, flow_reason: timeout, tcp_tcp_flags: df, tcp_tcp_flags_ts: de, tcp_tcp_flags_tc: 1b, tcp_syn: True, tcp_fin: True, tcp_rst: True, tcp_psh: True, tcp_ack: True, tcp_ecn: True, tcp_cwr: True, tcp_state: closed ; pcap_cnt: 47739, event_type: http, proto: TCP, tx_id: 0, http_url: /, http_http_content_type: text/html, http_http_method: GET, http_protocol: HTTP/1.0, http_status: 200, http_length: 774 ; event_type: fileinfo, proto: TCP, http_url: /, http_http_content_type: text/html, http_http_method: GET, http_protocol: HTTP/1.0, http_status: 200, http_length: 774, app_proto: http, fileinfo_filename: /, fileinfo_gaps: False, fileinfo_state: CLOSED, fileinfo_stored: False, fileinfo_size: 774, fileinfo_tx_id: 0',
"""),
			"iocs" : ["172.32.0.2"]
		}

	def get_iocs(self, state):
		return state


	def summarize(self, state):
		pass


	# def check_email(self, state):
	# 	print("# Checking for new emails")
	# 	search = GmailSearch(api_resource=self.gmail.api_resource)
	# 	emails = search('after:newer_than:1d')
	# 	checked_emails = state['checked_emails_ids'] if state['checked_emails_ids'] else []
	# 	thread = []
	# 	new_emails = []
	# 	for email in emails:
	# 		if (email['id'] not in checked_emails) and (email['threadId'] not in thread) and ( os.environ['MY_EMAIL'] not in email['sender']):
	# 			thread.append(email['threadId'])
	# 			new_emails.append(
	# 				{
	# 					"id": email['id'],
	# 					"threadId": email['threadId'],
	# 					"snippet": email['snippet'],
	# 					"sender": email["sender"]
	# 				}
	# 			)
	# 	checked_emails.extend([email['id'] for email in emails])
	# 	return {
	# 		**state,
	# 		"emails": new_emails,
	# 		"checked_emails_ids": checked_emails
	# 	}

	# def wait_next_run(self, state):
	# 	print("## Waiting for 180 seconds")
	# 	time.sleep(180)
	# 	return state

	# def new_emails(self, state):
	# 	if len(state['emails']) == 0:
	# 		print("## No new emails")
	# 		return "end"
	# 	else:
	# 		print("## New emails")
	# 		return "continue"

