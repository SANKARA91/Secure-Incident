import requests
import urllib3
from app.core.config import settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhConnector:
    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool | None = None,
        verify: bool | None = None,  # Ajout pour compatibilité
        base_url: str | None = None,
    ):
        # Préférence au base_url explicite, sinon on compose avec host+port
        if base_url:
            self.base = base_url.rstrip("/")
        else:
            _host = host or settings.WAZUH_HOST
            _port = port or settings.WAZUH_PORT
            self.base = f"https://{_host}:{_port}"

        self.username = username or settings.WAZUH_USERNAME
        self.password = password or settings.WAZUH_PASSWORD
        self.auth = (self.username, self.password)
        
        # Gérer à la fois 'verify' et 'verify_ssl' pour la compatibilité
        if verify is not None:
            self.verify = verify
        elif verify_ssl is not None:
            self.verify = verify_ssl
        else:
            self.verify = settings.VERIFY_SSL
            
        self.token = None

    def authenticate(self):
        url = f"{self.base}/security/user/authenticate?raw=true"  # ⚠️ indispensable
        r = requests.post(url, auth=self.auth, verify=self.verify, timeout=10)
        if r.status_code != 200 or not r.text.strip():
            raise requests.HTTPError(
                f"Auth failed ({r.status_code}) for user '{self.username}': {r.text}",
                response=r
            )
        self.token = r.text.strip()
        return self.token

    def _headers(self):
        if not self.token:
            self.authenticate()
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, endpoint: str, params: dict | None = None):
        url = f"{self.base}{endpoint}"
        r = requests.get(url, headers=self._headers(), params=params, verify=self.verify, timeout=20)
        if r.status_code == 401:  # token expiré → re-auth + retry
            self.authenticate()
            r = requests.get(url, headers=self._headers(), params=params, verify=self.verify, timeout=20)
        r.raise_for_status()
        return r.json()