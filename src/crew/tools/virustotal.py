import json
from langchain.tools import tool, BaseTool
import os, requests
from langchain_ollama import OllamaLLM


def format_virustotal_results(results):
    """
    This function takes the raw results from a VirusTotal scan and returns a human-readable string.

    Parameters:
    results (dict): The raw results from a VirusTotal scan.

    Returns:
    str: A formatted string summarizing the scan results.
    """
    md5 = results.get('md5', 'N/A')
    sha1 = results.get('sha1', 'N/A')
    sha256 = results.get('sha256', 'N/A')
    scan_date = results.get('scan_date', 'N/A')
    positives = results.get('positives', 'N/A')
    total = results.get('total', 'N/A')
    permalink = results.get('permalink', 'N/A')

    formatted_results = [
        f"VirusTotal Scan Results:",
        f"========================",
        f"MD5: {md5}",
        f"SHA-1: {sha1}",
        f"SHA-256: {sha256}",
        f"Scan Date: {scan_date}",
        f"Detections: {positives}/{total}",
        f"Detailed Report: {permalink}",
        "",
        "Detailed Scan Results:",
        "======================"
    ]

    scans = results.get('scans', {})
    for scanner, scan_data in scans.items():
        detected = scan_data.get('detected', False)
        result = scan_data.get('result', 'N/A')
        version = scan_data.get('version', 'N/A')
        update = scan_data.get('update', 'N/A')

        formatted_results.append(
            f"Scanner: {scanner}\n"
            f"  Detected: {'Yes' if detected else 'No'}\n"
            f"  Result: {result}\n"
            f"  Version: {version}\n"
            f"  Last Update: {update}\n"
        )

    return "\n".join(formatted_results)


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
        
        llm = OllamaLLM(
    	# model="ollama/hf.co/MaziyarPanahi/Mistral-Nemo-Instruct-2407-GGUF:Q4_K_M",
		model="openhermes",
    	base_url="http://localhost:11434",
        temperature=0.1,
        max_tokens=100,
		)
        
        aggregated_chunks = f"Scan results for files that communicate with {resource}: \n"

        for i in range(len(data['data'])):
            if 'attributes' in data['data'][i] and 'last_analysis_results' in data['data'][i]['attributes']:
                # Remove 'last_analysis_results' key from attributes
                del data['data'][i]['attributes']['last_analysis_results']
                aggregated_chunks += llm.invoke(f"This is a log entry for a VirusTotal scan result. Shorten this log entry keeping only the important information about the result : " + str(data['data'][i])) + "\n"
                # aggregated_chunks += llm.invoke(f"The following is a VirusTotal scan for communicating file with the IOC {resource}. Your role is to summarize the result in key bullet points only, while preserving the important information that might help regarding our analysis:" + str(data['data'][i])) + "\n"
    
        return aggregated_chunks