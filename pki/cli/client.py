import base64
import json
import urllib.error
import urllib.parse
import urllib.request


def _normalize_base_url(base_url: str) -> str:
    return base_url if base_url.endswith('/') else base_url + '/'


def _join_url(base_url: str, path: str) -> str:
    return urllib.parse.urljoin(_normalize_base_url(base_url), path.lstrip('/'))


def _parse_response_body(raw: bytes):
    if not raw:
        return {}
    text = raw.decode('utf-8', errors='replace')
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


class APIClient:
    def __init__(self, *, base_url: str, username: str, password: str, timeout: float):
        if not username or password is None:
            raise ValueError('Basic auth requires --username and --password.')

        token = base64.b64encode(f'{username}:{password}'.encode('utf-8')).decode('ascii')
        self.base_url = _normalize_base_url(base_url)
        self.timeout = timeout
        self.default_headers = {
            'Accept': 'application/json',
            'Authorization': f'Basic {token}',
        }

    def request(self, method: str, path: str, payload: dict | None = None):
        headers = dict(self.default_headers)
        data = None
        if payload is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(payload).encode('utf-8')

        request = urllib.request.Request(
            url=_join_url(self.base_url, path),
            method=method.upper(),
            headers=headers,
            data=data,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, _parse_response_body(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, _parse_response_body(exc.read())
