# backend/app/services/indexer_client.py
import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class IndexerClient:
    def __init__(self, base="https://192.168.1.19:9200", user="wazuh", password="WzH@2025!Secure+Admin_99", verify=False):
        self.base = base.rstrip("/")
        self.auth = (user, password)
        self.verify = verify

    def search(self, index_pattern: str, query: str, size: int = 500):
        url = f"{self.base}/{index_pattern}/_search"
        body = {
            "size": size,
            "query": {"query_string": {"query": query}}
        }
        r = requests.post(url, json=body, auth=self.auth, verify=self.verify, timeout=30)
        r.raise_for_status()
        return r.json()
