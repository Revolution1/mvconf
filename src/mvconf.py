#!/usr/bin/env python

import argparse
import json
import logging
import re
import sys
from os import path

__version__ = '0.2.0'
SOURCE_ROOT = path.abspath(path.dirname(__file__))
sys.path.append(SOURCE_ROOT)

import docker
import docker.types
from docker.errors import APIError
from ipaddress import IPv4Address
from ipaddress import IPv4Interface

from docker_client import docker_client, get_node_clients
from utils import memoize, ip_pool_iter

log = logging.getLogger('mvconf')
handler = logging.StreamHandler()
log.addHandler(handler)
log.setLevel(logging.INFO)


def check_is_manager():
    try:
        docker_client().nodes()
    except Exception:
        logging.error("Should run on manager node.")


def collect_used_ips(clients):
    # node_ip
    ips = {IPv4Address(n.get('Status', {}).get('Addr')) for n in docker_client().nodes()}
    # macvlans
    for client in clients:
        macvlans = [n for n in client.networks() if n.get('Driver') == 'macvlan']
        for mv in macvlans:
            net = client.inspect_network(mv.get('Id'))
            for container in net.get('Containers', {}).values():
                ips.add(IPv4Interface(container.get('IPv4Address')).ip)
    return ips


@memoize
def get_node_id_hostname_map():
    nodes = docker_client().nodes()
    return {n.get('ID'): n.get('Description', {}).get('Hostname') for n in nodes}


def check_config(conf_path):
    if not path.isfile(conf_path):
        log.error("Configuration file '%s' does not exist or it's a directory.\nUse %s --help to get more help."
                  % (conf_path, sys.argv[0]))
        sys.exit(1)
    with open(conf_path) as f:
        config = json.load(f)
    unknown_keys = set(config.keys()) - {'networks', 'services', 'auth'}
    if unknown_keys:
        log.error("Detected unknown keys: %s in config file" % ','.join(unknown_keys))
        sys.exit(1)
    return config


def get_service_running_tasks(name):
    c = docker_client()
    c.inspect_service(name)
    tasks = c.tasks(filters={'service': name})
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
    tasks = get_service_running_tasks(name)
    hostnames = []
    containers_host_map = {}
    for task in tasks:
        node_id = task.get('NodeID')
        hostname = get_node_id_hostname_map()[node_id]
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
    tasks = get_service_running_tasks(name)
    hostnames = []
    containers_host_map = {}
    for task in tasks:
        node_id = task.get('NodeID')
        hostname = get_node_id_hostname_map()[node_id]
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


def main():
    p = argparse.ArgumentParser(
        description="Script to Create MACVLAN, Bind Network to each container in Service <For SPD Bank>")
    p.add_argument('-f', '--config-file', dest='conf_path', type=str,
                   help="config file location, default: ./conf.json")
    p.add_argument('-d', '--disconnect', dest='disconnect', action='store_true',
                   help="Disconnect each container in service from network")
    p.add_argument('-r', '--remove-networks', dest='remove', action='store_true', help="Remove networks from each host")
    p.add_argument('-v', '--version', action='version', version=__version__)
    arg = p.parse_args()
    check_is_manager()
    conf_path = arg.conf_path or path.abspath(path.join(SOURCE_ROOT, './conf.json'))
    config = check_config(conf_path)
    username = config.get('auth', {}).get('username')
    password = config.get('auth', {}).get('password')
    node_clients = get_node_clients(username, password)
    networks = config.get('networks', [])
    services = config.get('services', [])
    if not (arg.disconnect or arg.remove):
        for network in networks:
            log.info("Creating network '%s'..." % network.get('name'))
            create_network(clients=node_clients, **network)
            log.info('Creating network done.')
        for service in services:
            log.info("Connecting service '%s' to network '%s'..." % (service.get('name'), service.get('network')))
            connect_service(clients=node_clients, **service)
            log.info('Connecting service done.')
    else:
        if arg.disconnect:
            for service in services:
                log.info("Disconnect service '%s' from network '%s'..." % (service.get('name'), service.get('network')))
                disconnect_service(clients=node_clients, **service)
                log.info('Disconnect service done.\n')
        if arg.remove:
            for network in networks:
                log.info("Removing network '%s'..." % network.get('name'))
                remove_network(clients=node_clients, **network)
                log.info('Removing network done.\n')


if __name__ == '__main__':
    main()
