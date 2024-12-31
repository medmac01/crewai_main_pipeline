import requests
from langchain.tools import tool
from datetime import datetime, timedelta

def get_day_suffix(day):
    if 4 <= day <= 20 or 24 <= day <= 30:
        return "th"
    else:
        return ["st", "nd", "rd"][day % 10 - 1]

def format_cve(cve_response, mode="normal", keyword=""):
    """
    Takes a dictionary representing the API response and formats each CVE entry into a structured prompt for LLM.
    
    Parameters:
    - cve_response: A dictionary representing the API response containing CVE information.
    
    Returns:
    - A list of strings, each a formatted prompt for LLM based on the CVE entries in the response.
    """

    # Get the current date and time
    now = datetime.now()
    day = now.day

    formatted_prompts = f"CVE Search Results for {keyword}:\n\n \n " if mode == "normal" else f"""Latest CVEs for {now.strftime(f"%A, %B {day}{get_day_suffix(day)} %Y")} related to {keyword} :\n\n"""
    
    if len(cve_response['vulnerabilities']) == 0:

        formatted_prompts = "No CVEs found matching the search criteria."
        return formatted_prompts
    
    
    for vulnerability in cve_response['vulnerabilities']:
        cve = vulnerability.get('cve', {})
        prompt = f"- CVE ID: {cve.get('id', 'N/A')}\n"
        prompt += f"- Status: {cve.get('vulnStatus', 'Unknown')}\n"
        
        if mode == "normal":
            descriptions = cve.get('descriptions', [])
            description_text = descriptions[0].get('value', 'No description available.') if descriptions else "No description available."
            prompt += f"- Description: {description_text}\n"
            
        if 'metrics' in cve and 'cvssMetricV2' in cve['metrics']:
            cvss_metrics = cve['metrics']['cvssMetricV2'][0]
            prompt += f"- CVSS Score: {cvss_metrics.get('cvssData', {}).get('baseScore', 'Not available')} ({cvss_metrics.get('baseSeverity', 'Unknown')})\n"
        else:
            prompt += "- CVSS Score: Not available\n"
        
        configurations = cve.get('configurations', {})
        for conf in configurations:
            nodes = conf.get('nodes', [])
            affected_configs = []
            for node in nodes:
                for cpe_match in node.get('cpeMatch', []):
                    if cpe_match.get('vulnerable', False):
                        affected_configs.append(cpe_match.get('criteria', 'Not specified'))
            prompt += f"- Affected Configurations: {', '.join(affected_configs) if affected_configs else 'Not specified'}\n"
        
        if mode == "normal":
            references = cve.get('references', [])
            ref_urls = ', '.join([ref.get('url', 'No URL') for ref in references])
            prompt += f"- References: {ref_urls if references else 'No references available.'}\n"
            
        
        formatted_prompts += prompt+"\n\n"
    
    return formatted_prompts

class CVESearchTool():
  @tool("CVE search Tool", return_direct=True)
  def cvesearch(keyword: str, date: str = None):
    """
    Searches for CVEs based on a keyword or phrase and returns the results in JSON format.
    Use this when a user asks you about a certain CVE or a CVE related to a certain keyword. 
    And not necesserly the latest CVEs.
    Parameters:
    - keyword (str): A word or phrase to search for in the CVE descriptions.
    - date (str): An optional date to include in the search query.
    
    Returns:
    - JSON: A list of CVEs matching the keyword search.
    """

    if date:
        keyword = f"{keyword} {date}"
    # Encode the spaces in the keyword(s) as "%20" for the URL
    keyword_encoded = keyword.replace(" ", "%20")
    
    # Construct the URL for the API request
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword_encoded}&resultsPerPage=3"
    
    try:
        # Send the request to the NVD API
        response = requests.get(url)
        # Check if the request was successful
        if response.status_code == 200:
            # Return the JSON response
            formatted = format_cve(response.json(), mode="normal", keyword=keyword)
            return formatted
        else:
            return {"error": "Failed to fetch data from the NVD API.", "status_code": response.status_code}
    except Exception as e:
        return {"error": str(e)}