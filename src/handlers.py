import base64
import json
import logging
import os
import re
import sys
from os import path
from urlparse import urlparse

import docker
import docker.types
from docker.errors import APIError
from ipaddress import IPv4Address
from ipaddress import IPv4Interface

from dce_client import DCEClient
from docker_client import docker_client, get_dce_client, get_node_clients
from utils import memoize, ip_pool_iter

log = logging.getLogger('mvconf')
handler = logging.StreamHandler()
log.addHandler(handler)
log.setLevel(logging.INFO)

__controller_client = None


def get_manager_client(clients):
    global __controller_client
    if __controller_client:
        return __controller_client
    for client in clients:
        try:
            client.nodes()
            __controller_client = client
            return client
        except:
            pass


def collect_used_ips(clients):
    # node_ip
    manager_client = get_manager_client(clients)
    ips = {IPv4Address(n.get('Status', {}).get('Addr')) for n in manager_client.nodes()}
    # macvlans
    for client in clients:
        macvlans = [n for n in client.networks() if n.get('Driver') == 'macvlan']
        for mv in macvlans:
            net = client.inspect_network(mv.get('Id'))
            for container in net.get('Containers', {}).values():
                ips.add(IPv4Interface(container.get('IPv4Address')).ip)
    return ips


def collect_macvlan_status(clients):
    containers = []
    for client in clients:
        macvlans = [n for n in client.networks() if n.get('Driver').lower() == 'macvlan']
        for mv in macvlans:
            net = client.inspect_network(mv.get('Id'))
            for cid, v in net.get('Containers', {}).items():
                containers.append({
                    'id': cid[:12],
                    'name': v.get('Name'),
                    'network_name': mv.get('Name'),
                    'service_name': '.'.join(v.get('Name').split('.')[:-2]),
                    'hostname': client.hostname,
                    'host_ip': client.address,
                    'ip': v.get('IPv4Address')
                })
    return containers


@memoize
def get_node_id_hostname_map(manager_client):
    nodes = manager_client.nodes()
    return {n.get('ID'): n.get('Description', {}).get('Hostname') for n in nodes}


def get_service_running_tasks(name, manager_client):
    manager_client.inspect_service(name)
    tasks = manager_client.tasks(filters={'service': name})
    return [t for t in tasks if t.get('Status', {}).get('State') == 'running']


def create_network(clients, name, subnet, gateway, parent, ip_range=None):
    log.info(json.dumps({
        'NetWork': name,
        'Subnet': subnet,
        'Gateway': gateway,
        'Parent': parent,
        'IP Range': ip_range
    }, indent=2))

    ipam_pool = docker.types.IPAMPool(
        subnet=subnet,
        iprange=ip_range,
        gateway=gateway,
    )

    ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
    for client in clients:
        log.info("--> Creating network '%s' on host '%s'" % (name, client.hostname))
        try:
            client.create_network(name, driver='macvlan', ipam=ipam_config, options={'parent': parent})
        except APIError as e:
            try:
                client.inspect_network(name)
                log.info("--> Host '%s' already has a network '%s' skipping." % (client.hostname, name))
            except APIError:
                log.error('--> Docker APIError: %s' % e)
        except Exception:
            log.exception("--> Fail.")


def remove_network(clients, name, *args, **kwargs):
    for client in clients:
        log.info('--> Removing network %s from host %s' % (name, client.hostname))
        try:
            net_id = client.inspect_network(name).get('Id')
            client.remove_network(net_id)
        except APIError as e:
            if e.status_code == 404:
                log.error('--> Network %s not found on host %s' % (name, client.hostname))
                return
            log.error('--> Docker APIError: %s' % e)
        except Exception:
            log.exception("--> Fail.")


class NextContainer(Exception):
    pass


def connect_service(clients, name, network, ip_pool=None):
    log.info(json.dumps({
        'Service': name,
        'Network': network,
        'IP Pool': ip_pool,
    }, indent=2))
    pool = set()
    if ip_pool:
        pool = set(ip_pool_iter(ip_pool)) - collect_used_ips(clients)
        if not pool:
            log.error('--> No avaliable ip in ip pool, abort.')
            return
    tasks = get_service_running_tasks(name, get_manager_client(clients))
    hostnames = []
    containers_host_map = {}
    for task in tasks:
        node_id = task.get('NodeID')
        hostname = get_node_id_hostname_map(get_manager_client(clients))[node_id]
        hostnames.append(hostname)
        containers_host_map.setdefault(hostname, []) \
            .append(task.get('Status', {}).get('ContainerStatus', {}).get('ContainerID'))

    def _connect(client, container_id, network, ip=None):
        log.info("--> Connecting container '%s' to MACVLAN '%s' on host '%s' with ip '%s'..."
                 % (container_id[:8], network, client.hostname, ip or 'AUTO'))
        try:
            net_id = client.inspect_network(network).get('Id')
            client.connect_container_to_network(container_id, net_id, ipv4_address=ip)
            return True
        except APIError as e:
            if e.status_code == 404:
                log.error("--> Network %s not found on host '%s'" % (network, client.hostname))
                raise NextContainer
            if e.status_code == 500 and re.search(r'already exists in network', e.explanation):
                log.info("--> Container '%s' already in network '%s'" % (container_id[:8], network))
                raise NextContainer
            log.error("--> Docker APIError: %s" % e)
        except Exception:
            log.exception("--> Fail.")

    for client in clients:
        if not client.hostname in hostnames:
            continue
        for container_id in containers_host_map[client.hostname]:
            if ip_pool:
                if not pool:
                    log.error("--> Ran out of ip in IP Pool, aborting...")
                while pool:
                    _ip = pool.pop()
                    try:
                        if _connect(client, container_id, network, str(_ip)):
                            break
                    except NextContainer:
                        pool.add(_ip)
                        break
            else:
                _connect(client, container_id, network)


def disconnect_service(clients, name, network, *args, **kwargs):
    tasks = get_service_running_tasks(name, get_manager_client(clients))
    hostnames = []
    containers_host_map = {}
    for task in tasks:
        node_id = task.get('NodeID')
        hostname = get_node_id_hostname_map(get_manager_client(clients))[node_id]
        hostnames.append(hostname)
        containers_host_map.setdefault(hostname, []) \
            .append(task.get('Status', {}).get('ContainerStatus', {}).get('ContainerID'))

    for client in clients:
        if not client.hostname in hostnames:
            continue
        for container_id in containers_host_map[client.hostname]:
            try:
                net_id = client.inspect_network(network).get('Id')
            except APIError as e:
                if e.status_code == 404:
                    log.error('--> Network %s not found on host %s' % (network, client.hostname))
                else:
                    log.error('--> Docker APIError: %s' % e)
                break
            log.info("--> Disconnecting container %s from MACVLAN %s on host %s..."
                     % (container_id[:8], network, client.hostname))
            try:
                client.disconnect_container_from_network(container_id, net_id)
            except APIError as e:
                log.error('--> Docker APIError: %s' % e)
            except Exception:
                log.exception("--> Fail.")


class DCEAuth(object):
    def __init__(self, auth_path='~/.dce_auth', url=None, username=None, password=None):
        self.auth_path = os.path.expanduser(auth_path)
        self.url = url
        self.username = username
        self.password = password

    @classmethod
    def load_auth(cls, auth_path='~/.dce_auth'):
        auth_path = os.path.expanduser(auth_path)
        if not os.path.isfile(auth_path):
            return
        with open(auth_path) as f:
            url, auth = json.load(f).items()[0]
            username, password = base64.b64decode(auth).split(':')
            return cls(auth_path, url, username, password)

    @classmethod
    def login(cls, url, username, password, auth_path='~/.dce_auth'):
        try:
            DCEClient(url, username, password).nodes()
        except Exception as e:
            log.error("DCE login Fail: %s" % e)
            return
        return cls(auth_path, url, username, password)

    def dce_client(self):
        return DCEClient(self.url, self.username, self.password)

    def docker_client(self):
        return self.dce_client().docker_client(urlparse(self.url).netloc.split(':')[0])

    def save(self):
        data = {
            self.url: base64.b64encode('%s:%s' % (self.username, self.password))
        }
        with open(self.auth_path, 'wb') as f:
            json.dump(data, f)

    def __repr__(self):
        return '<DCEAuth of %s>' % self.url


def check_config(config):
    unknown_keys = set(config.keys()) - {'networks', 'services', 'auth'}
    if unknown_keys:
        log.error("Detected unknown keys: %s in config file" % ','.join(unknown_keys))
        return
    return config


def get_config(conf_file, exit=True):
    if not path.isfile(conf_file):
        if exit:
            log.error("Configuration file '%s' does not exist or it's a directory." % conf_file)
            sys.exit(1)
    try:
        with open(conf_file) as f:
            return json.load(f)
    except Exception as e:
        log.debug(e)
    return {}


def get_docker_client_auth(conf_file=None):
    local_auth = DCEAuth.load_auth()
    try:
        # Try login DCE without auth
        c = get_dce_client()
        c.nodes()
        return docker_client(), DCEAuth()
    except Exception:
        log.debug("Try login DCE without auth, fail.")
        config = get_config(conf_file, False) if conf_file else {}
        auth = config.get('auth', {})
        if not local_auth and not auth:
            log.error(
                "DCE Authenticate fail, please specify 'auth' in config file or use command '%s login'." % sys.argv[0])
            sys.exit(1)
        if auth:
            # Try login DCE with config file
            url = auth.get('url', 'auto')
            password = auth.get('password')
            username = auth.get('username')
            if url == 'auto':
                c = docker_client()
                try:
                    # Try login DCE with config file and auto detected url
                    get_dce_client(username, password, c).nodes()
                    return c, DCEAuth(url, username, password)
                except Exception as e:
                    log.error('Auth from config file with auto-detect url fail: %s' % e)
            else:
                # Try login DCE with config file
                if not url.startswith('http'):
                    url = 'http://' + url
                try:
                    dce_auth = DCEAuth.login(url, password, username)
                    if dce_auth:
                        return dce_auth.dce_client().docker_client(urlparse(url).netloc.split(':')[0]), dce_auth
                except Exception as e:
                    log.error('Auth from config file fail: %s' % e)
        if local_auth:
            return local_auth.docker_client(), local_auth
        return None, DCEAuth()


if __name__ == '__main__':
    c, a = get_docker_client_auth()
    cs = get_node_clients('admin', 'admin', c)
    print collect_macvlan_status(cs)
