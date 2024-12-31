from langchain.tools import tool, BaseTool

class MISPSearchTool():
    @tool("MISP search tool", return_direct=False)
    def search_misp(iocs):
        """Search for Indicators of Compromise (IOCs) in MISP
        Parameters:
        - iocs: A list of IOCs to search for
        Returns:
        - The search results
        """
        return str("""{
  "Event": {
    "info": "Suspicious DHCP and HTTP Activity Detected",
    "threat_level_id": "3",
    "analysis": "0",
    "Attribute": [
      {
        "type": "ip-src",
        "category": "Network activity",
        "value": "172.31.69.18",
        "to_ids": true
      },
      {
        "type": "ip-dst",
        "category": "Network activity",
        "value": "194.233.80.217",
        "to_ids": true
      },
      {
        "type": "hostname",
        "category": "Network activity",
        "value": "ip-172-31-69-18",
        "to_ids": false
      },
      {
        "type": "mac-address",
        "category": "Network activity",
        "value": "02:62:a9:6f:87:18",
        "to_ids": false
      },
      {
        "type": "text",
        "category": "Payload delivery",
        "value": "DHCP request with parameters: subnet_mask, router, domain, dns_server, ntp_server",
        "to_ids": false
      },
      {
        "type": "ip-dst",
        "category": "Network activity",
        "value": "172.31.0.2",
        "to_ids": false,
        "comment": "DNS server in DHCP reply"
      },
      {
        "type": "ip-dst",
        "category": "Network activity",
        "value": "172.31.69.1",
        "to_ids": false,
        "comment": "Router in DHCP reply"
      },
      {
        "type": "http-method",
        "category": "Network activity",
        "value": "GET",
        "to_ids": false
      },
      {
        "type": "url",
        "category": "Network activity",
        "value": "/",
        "to_ids": false,
        "comment": "HTTP request URL"
      },
      {
        "type": "http-status",
        "category": "Network activity",
        "value": "200",
        "to_ids": false
      },
      {
        "type": "size-in-bytes",
        "category": "Payload delivery",
        "value": "774",
        "to_ids": false,
        "comment": "HTTP response size"
      }
    ],
    "Tag": [
      {
        "name": "network:dhcp"
      },
      {
        "name": "network:http"
      },
      {
        "name": "suspicious-activity"
      }
    ]
  }
}
""")