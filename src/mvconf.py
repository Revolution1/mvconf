#!/usr/bin/env python

import argparse
import json
import logging
import sys
from os import path

import docker
import docker.types
from docker.errors import APIError
from ipaddress import IPv4Address
from ipaddress import IPv4Interface

from docker_client import docker_client, get_node_clients
from utils import memoize, ip_pool_iter

__version__ = '0.2.0'
SOURCE_ROOT = path.abspath(path.dirname(__file__))
sys.path.append(SOURCE_ROOT)

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
    tasks = docker_client().tasks(filters={'service': name})
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
        log.info('--> Creating network %s on host %s' % (name, client.hostname))
        try:
            client.create_network(name, driver='macvlan', ipam=ipam_config, options={'parent': parent})
        except APIError as e:
            log.error('--> Docker APIError: %s' % e)
        except Exception:
            log.exception("--> Fail.")


def connect_service(clients, name, network, ip_pool=None):
    log.info(json.dumps({
        'Service': name,
        'Network': network,
        'IP Pool': ip_pool,
    }, indent=2))
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

    for client in clients:
        if not client.hostname in hostnames:
            continue
        net_id = client.inspect_network(network).get('Id')
        for container_id in containers_host_map[client.hostname]:
            for ip in pool:
                log.info("--> Connecting container %s to MacVLan %s on host %s with ip %s..."
                         % (container_id, network, client.hostname, ip))
                try:
                    client.connect_container_to_network(container_id, net_id, ipv4_address=str(ip))
                    break
                except APIError as e:
                    log.error('--> Docker APIError: %s' % e)
                except Exception:
                    log.exception("--> Fail.")


def main():
    p = argparse.ArgumentParser(description="Script to Create MacVLan, Bind Network to Service <For SPD Bank>")
    p.add_argument('-f', '--config-file', dest='conf_path', type=str,
                   help="config file location, default: ./conf.json")
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
    for network in networks:
        log.info("Creating network %s..." % network.get('name'))
        create_network(clients=node_clients, **network)
        log.info('done.')
    for service in services:
        log.info("Connecting service %s to network %s..." % (service.get('name'), service.get('network')))
        connect_service(clients=node_clients, **service)
        log.info('done.')


if __name__ == '__main__':
    main()
