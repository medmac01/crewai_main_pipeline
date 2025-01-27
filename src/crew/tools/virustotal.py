import json
from langchain.tools import tool, BaseTool
import os, requests
from datetime import datetime
from langchain_ollama import OllamaLLM

def format_vt_communicating_files(vt_response):
    # Helper function to convert timestamps to human-readable dates
    def format_date(timestamp):
        return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d') if timestamp else "N/A"

    formatted_files = []
    for item in vt_response.get('data', []):
        attributes = item.get('attributes', {})
        
        # Collect relevant fields
        file_info = {
            "Scanned": format_date(attributes.get('last_analysis_date', 0)),
            "Detections": f"{attributes.get('last_analysis_stats', {}).get('malicious', 0)} / {sum(attributes.get('last_analysis_stats', {}).values())}",
            "Type": attributes.get('type_description', 'N/A'),
            "Tags": attributes.get('tags', []),
            "Name": attributes.get('meaningful_name', attributes.get('sha256', 'Unknown'))
        }
        
        formatted_files.append(file_info)
    
    return formatted_files


class VTTool(BaseTool):
    name : str = "VirusTotal Scanner"
    description : str = "A tool for scanning files, URLs, and IP addresses using VirusTotal."
    return_direct : bool = True

    def _run(self, resource : str, scan_type : str = 'hash') -> str:
        base_url = 'https://www.virustotal.com/vtapi/v2/'
        api_key = os.getenv('VIRUSTOTAL_API_KEY')

        # Determine if the resource is a hash, URL, or IP based on scan_type
        if scan_type == 'url' or (resource.startswith('http://') or resource.startswith('https://')):
            # It's a URL
            params = {'apikey': api_key, 'url': resource}
            scan_url = base_url + 'url/scan'
            report_url = base_url + 'url/report'
            response = requests.post(scan_url, data=params)  # Submit the URL for scanning
            response.raise_for_status()  # Raise an error for bad status codes

        elif scan_type == 'ip':
            # It's an IP address
            params = {'apikey': api_key, 'ip': resource}
            scan_url = base_url + 'ip-address/report'
            report_url = base_url + 'ip-address/report'
            
        else:
            # Assume it's a hash
            params = {'apikey': api_key, 'resource': resource}
            scan_url = base_url + 'file/report'
            report_url = base_url + 'file/report'
        
        # Now, retrieve the scan report
        response = requests.get(report_url, params=params)
        response.raise_for_status()  # Raise an error for bad status codes
        return str(response.json())

class VirusTotalTool:
    @tool("VirusTotal scanner", return_direct=False)
    def scanner(resource: str, scan_type: str = 'hash'):
        """Useful tool to scan a hash or URL using VirusTotal
        Parameters:
        - hash: The hash to scan
        - url: The URL to scan
        - scan_type: The type of resource to scan (hash, ip or url)
        Returns:
        - The scan results
        """
        base_url = 'https://www.virustotal.com/api/v3/'
        api_key = '08c94f232e2dde41119539bd1aaa214d2828c4a49f13b860fe385dc84a4955ab'

        # Determine if the resource is a hash, URL, or IP based on scan_type
        if scan_type == 'url' or (resource.startswith('http://') or resource.startswith('https://')):
            # It's a URL
            params = {'apikey': api_key, 'url': resource}
            scan_url = base_url + 'url/scan'
            report_url = base_url + 'url/report'
            response = requests.post(scan_url, data=params)  # Submit the URL for scanning
            response.raise_for_status()  # Raise an error for bad status codes

        elif scan_type == 'ip':
            # It's an IP address
            params = {'x-apikey': api_key}
            import requests


            params = {
                "accept": "application/json",
                "x-apikey": "08c94f232e2dde41119539bd1aaa214d2828c4a49f13b860fe385dc84a4955ab"
}
            
            scan_url = base_url + 'ip_addresses/' + resource
            report_url = base_url + 'ip_addresses/' + resource
            # report_url = base_url + 'ip-address/report'
            
        else:
            # Assume it's a hash
            params = {'apikey': api_key, 'resource': resource}
            scan_url = base_url + 'file/report'
            report_url = base_url + 'file/report'
        
        # Now, retrieve the scan report
        response = requests.get(report_url, headers=params)
        response.raise_for_status()  # Raise an error for bad status codes

        data = response.json()
        
        if 'attributes' in data['data'] and 'last_analysis_results' in data['data']['attributes']:
        # Remove 'last_analysis_results' key from attributes
            del data['data']['attributes']['last_analysis_results']
    
        return str(data)

    @tool("VirusTotal scan communicating files", return_direct=True)
    def scan_related_files(resource: str, scan_type: str = 'ip'):
        """Useful tool to retrieve communicating files for an IP address using VirusTotal
        Parameters:
        - hash: The hash to scan
        - url: The URL to scan
        - scan_type: The type of resource to scan (hash, ip or url)
        Returns:
        - The scan results
        """
        base_url = 'https://www.virustotal.com/api/v3/'
        api_key = '08c94f232e2dde41119539bd1aaa214d2828c4a49f13b860fe385dc84a4955ab'

        # Determine if the resource is a hash, URL, or IP based on scan_type
        if scan_type == 'url' or (resource.startswith('http://') or resource.startswith('https://')):
            # It's a URL
            params = {'apikey': api_key, 'url': resource}
            scan_url = base_url + 'url/scan'
            report_url = base_url + 'url/report'
            response = requests.post(scan_url, data=params)  # Submit the URL for scanning
            response.raise_for_status()  # Raise an error for bad status codes

        elif scan_type == 'ip':
            # It's an IP address
            params = {'x-apikey': api_key}
            import requests


            params = {
                "accept": "application/json",
                "x-apikey": "08c94f232e2dde41119539bd1aaa214d2828c4a49f13b860fe385dc84a4955ab"
}
            
            scan_url = base_url + 'ip_addresses/' + resource + "/communicating_files?limit=10"
            report_url = base_url + 'ip_addresses/' + resource + "/communicating_files?limit=10"
            # report_url = base_url + 'ip-address/report'
            
        else:
            # Assume it's a hash
            params = {'apikey': api_key, 'resource': resource}
            scan_url = base_url + 'file/report'
            report_url = base_url + 'file/report'
        
        # Now, retrieve the scan report
        response = requests.get(report_url, headers=params)
        response.raise_for_status()  # Raise an error for bad status codes

        data = response.json()
        
        # llm = OllamaLLM(
    	# # model="ollama/hf.co/MaziyarPanahi/Mistral-Nemo-Instruct-2407-GGUF:Q4_K_M",
		# model="wrn",
    	# base_url="http://localhost:11434",
        # temperature=0.1,
        # max_tokens=75,
		# )
        
        aggregated_chunks = f"Scan results for files that communicate with {resource}: \n"

        for i in range(len(data['data'])):
            if 'attributes' in data['data'][i] and 'last_analysis_results' in data['data'][i]['attributes']:
                # Remove 'last_analysis_results' key from attributes
                del data['data'][i]['attributes']['last_analysis_results']
                # aggregated_chunks += llm.invoke(f"This is a log entry for a VirusTotal scan result. Shorten this log entry keeping only the important information about the result : " + str(data['data'][i])) + "\n"
                # aggregated_chunks += llm.invoke(f"The following is a VirusTotal scan for communicating file with the IOC {resource}. Your role is to summarize the result in key bullet points only, while preserving the important information that might help regarding our analysis:" + str(data['data'][i])) + "\n"
                
    
        return f"Scan results for files that communicate with {resource}: \n" + str(format_vt_communicating_files(data))