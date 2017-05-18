# encoding=utf-8
import logging
import os
import re
from functools import partial

import requests
import requests.exceptions
import six.moves
from docker import APIClient
from docker.tls import TLSConfig
from docker.transport import SSLAdapter, UnixAdapter
from docker.utils.utils import kwargs_from_env
from requests.packages import urllib3

from dce_client import DCEClient
from utils import memoize

try:
    from docker.transport import NpipeAdapter
except ImportError:
    pass

urllib3.disable_warnings()
SWARM_CLIENT = None
DOCKER_CLIENTS = {}
DEFAULT_TIMEOUT_SECONDS = 180

log = logging.getLogger('DCEDockerClient')


class DCEDockerClient(APIClient):
    def __init__(self, base_url=None, version=None,
                 token=None, timeout=5, hostname='',
                 user_agent='DiskCleaner/DCE-Plugin', tls=False, num_pools=25):
        super(DCEDockerClient, self).__init__()
        self._hostname = ''
        self._address = ''
        if base_url.startswith('http+unix://'):
            self._custom_adapter = UnixAdapter(
                base_url, timeout, pool_connections=num_pools
            )
            self.mount('http+docker://', self._custom_adapter)
            # self._unmount('http://', 'https://')
            self.base_url = 'http+docker://localunixsocket'
        else:
            # Use SSLAdapter for the ability to specify SSL version
            if isinstance(tls, TLSConfig):
                tls.configure_client(self)
            elif tls:
                self._custom_adapter = SSLAdapter(pool_connections=num_pools)
                self.mount('https://', self._custom_adapter)
            self.base_url = base_url
            self.timeout = timeout
            self.headers['User-Agent'] = user_agent
            self._version = version
            if token:
                self.headers['X-DCE-Access-Token'] = token
            self.request = self.request_
            self._url = self._url_
            self._version = self._retrieve_server_version()

    def request_(self, *args, **kwargs):
        kwargs.setdefault('verify', False)
        return requests.api.request(*args, **kwargs)

    def _url_(self, pathfmt, *args, **kwargs):
        for arg in args:
            if not isinstance(arg, six.string_types):
                raise ValueError(
                    'Expected a string but found {0} ({1}) '
                    'instead'.format(arg, type(arg))
                )

        quote_f = partial(six.moves.urllib.parse.quote_plus, safe="/:")
        args = map(quote_f, args)
        return '{0}{1}'.format(self.base_url, pathfmt.format(*args))

    @property
    def hostname(self):
        if not self._hostname:
            self._hostname = self.info()['Name']
        return self._hostname

    @property
    def address(self):
        if not self._address:
            self._address = self.info()['Swarm']['NodeAddr']
        return self._address

    def create_service_raw(self, service_spec, auth_header=None):
        headers = {}
        if auth_header:
            headers['X-Registry-Auth'] = auth_header

        url = self._url('/services/create')
        return self._result(self._post_json(url, data=service_spec, headers=headers), True)

    def update_service_raw(self, service_id, version, service_spec):
        url = self._url('/services/%s/update?version=%s' % (service_id, version))
        return self._result(self._post_json(url, data=service_spec), json=False)

    def __repr__(self):
        return '<DCEDockerClient of %s>' % self.hostname


def convert_docker_datetime(datetime_str):
    is_num = lambda c: re.match(r'\d', c) is not None
    p_pos = datetime_str.rfind('.')
    if p_pos < 0:
        return datetime_str
    tz_pos = None
    for i, c in enumerate(datetime_str[p_pos + 1:]):
        if not is_num(c):
            tz_pos = i + p_pos
            break

    micro_sec = datetime_str[p_pos:tz_pos][1:6]
    validated_datetime_str = datetime_str[:p_pos] + '.' + micro_sec
    if tz_pos:
        validated_datetime_str += datetime_str[tz_pos:]
    return validated_datetime_str


def check_kv_store_configured(docker_address):
    c = docker_client(base_url=docker_address, tls=True)
    info = c.info()
    cluster_store = info.get('ClusterStore')
    cluster_advertise = info.get('ClusterAdvertise')
    return True if (cluster_advertise and cluster_store) else False


def docker_client(base_url='http+unix://var/run/docker.sock', hostname='', timeout=DEFAULT_TIMEOUT_SECONDS, tls=False):
    if os.getenv('TEST'):
        base_url = 'http://192.168.56.102:1234'
    global DOCKER_CLIENTS

    if not base_url in DOCKER_CLIENTS:
        kwargs = kwargs_from_env(assert_hostname=False)
        kwargs['base_url'] = base_url
        kwargs['timeout'] = timeout
        kwargs['hostname'] = hostname
        DOCKER_CLIENTS[base_url] = DCEDockerClient(**kwargs)

    return DOCKER_CLIENTS[base_url]


def detect_dce_ports(client=None):
    """
    :return: (swarm_port, controller_port, controller_ssl_port)
    """
    client = client or docker_client()
    dce_base = client.inspect_service('dce_base')
    environments = dce_base.get('Spec', {}).get('TaskTemplate', {}).get('ContainerSpec', {}).get('Env', [])
    environments = dict(
        [e.split('=', 1) for e in environments if '=' in e]
    )
    (swarm_port, controller_port, controller_ssl_port) = (
        environments.get('SWARM_PORT'),
        environments.get('CONTROLLER_PORT'),
        environments.get('CONTROLLER_SSL_PORT')
    )
    ports = int(swarm_port), int(controller_port), int(controller_ssl_port)
    return ports


def _is_hsts_on(url):
    r = requests.get(url, allow_redirects=False)
    return r.status_code == 302 and r.headers.get('Location').startswith('https://')


def get_dce_client(username=None, password=None, client=None):
    c = client or docker_client()
    addr = c.info()['Swarm']['NodeAddr']
    _, port, ssl_port = detect_dce_ports(c)
    return DCEClient('http://%s:%s' % (addr, port), username=username, password=password)


@memoize
def get_node_clients(username, password, client=None):
    client = client or docker_client()
    log.debug("Getting node clients with username: %s, password: %s, client: %s" % (username, password, client))
    controllers = [n['ManagerStatus']['Addr'] for n in client.nodes() if n['Spec']['Role'] == 'manager']
    addr = controllers[0].split(':')[0]
    _, port, ssl_port = detect_dce_ports(client)
    proto = 'http'
    dce = DCEClient('%s://%s:%s' % (proto, addr, port), username, password)
    ip_map = dce.ip_map()
    return [docker_client('%s://%s/api/nodes/%s/docker' % (proto, addr, n.get('advertised_address')),
                          hostname=n.get('hostname')) for n in ip_map.values()]


if __name__ == '__main__':
    cc = docker_client('http://192.168.56.102:1234')
    print get_node_clients('admin', 'admin', cc)
