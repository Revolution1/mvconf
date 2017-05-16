import requests
from requests.auth import HTTPBasicAuth
from requests.packages import urllib3

urllib3.disable_warnings()


class DCEClient(requests.Session):
    def __init__(self, base_url=None,
                 username=None, password=None, timeout=60,
                 user_agent='DiskCleaner/DCE-Plugin'):
        super(DCEClient, self).__init__()
        if base_url.endswith('/'):
            base_url = base_url[:-1]
        self.base_url = base_url
        self.timeout = timeout
        self.headers['User-Agent'] = user_agent
        self.verify = False
        if username and password:
            self.auth = HTTPBasicAuth(username, password)

    def create_api_error_from_http_exception(self, e):
        """
        Create a suitable APIError from requests.exceptions.HTTPError.
        """
        response = e.response
        try:
            description = response.json()['message']
        except ValueError:
            description = response.content.strip()
        cls = IOError
        raise cls('{code}{message}'.format(message='Accessing DCE api error: %s' % description,
                                           code=response.status_code))

    def _raise_for_status(self, response):
        """Raises stored :class:`APIError`, if one occurred."""
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise self.create_api_error_from_http_exception(e)

    def _result(self, response, json=False, binary=False):
        assert not (json and binary)
        self._raise_for_status(response)

        if json:
            return response.json()
        if binary:
            return response.content
        return response.text

    def _set_request_timeout(self, kwargs):
        """Prepare the kwargs for an HTTP request by inserting the timeout
        parameter, if not already present."""
        kwargs.setdefault('timeout', self.timeout)
        return kwargs

    def _post(self, url, **kwargs):
        return self.post(url, **self._set_request_timeout(kwargs))

    def _get(self, url, **kwargs):
        return self.get(url, **self._set_request_timeout(kwargs))

    def _put(self, url, **kwargs):
        return self.put(url, **self._set_request_timeout(kwargs))

    def _delete(self, url, **kwargs):
        return self.delete(url, **self._set_request_timeout(kwargs))

    def _url(self, path, *args, **kwargs):
        return '{0}{1}'.format(self.base_url, path.format(*args))

    def nodes(self):
        return self._result(self._get(self._url('/nodes')), json=True)

    def ip_map(self):
        return self._result(self._get(self._url('/api/nodes-utils/ip-map')), json=True)

    def _lookup_ip(self, host):
        ip_map = self.ip_map()
        if host in ip_map:
            return ip_map[host]['advertised_ip']
        for h in ip_map.values():
            if h['hostname'] == host:
                return h['advertised_ip']
        return host

    def _lookup_id(self, host):
        ip_map = self.ip_map()
        for i, h in ip_map.items():
            if h['hostname'] == host or h['advertised_ip'] == host:
                return i
        return host

    def docker_client(self, host):
        from docker_client import docker_client

        return docker_client('{}/api/nodes/{}:12376/docker'.format(self.base_url, self._lookup_ip(host)))

    def sysinfo(self, host):
        return self._result(self._get(self._url('/api/nodes-utils/{}/sysinfo'.format(self._lookup_id(host)))),
                            json=True)

    def disk_usage(self, host):
        pass


if __name__ == '__main__':
    c = DCEClient('https://192.168.56.102', 'admin', 'admin')
    print c.ip_map()
