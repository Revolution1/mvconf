#!/usr/bin/env python
import json
import os
import sys
from collections import OrderedDict
from os import path

import click

from docker_client import get_node_clients
from handlers import DCEAuth
from handlers import check_config
from handlers import collect_macvlan_status
from handlers import connect_service
from handlers import create_network
from handlers import disconnect_service
from handlers import get_config
from handlers import get_docker_client_auth
from handlers import log
from handlers import remove_network
from version import version

SOURCE_ROOT = path.abspath(path.dirname(__file__))
sys.path.append(SOURCE_ROOT)


class AliasedGroup(click.Group):
    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        matches = [x for x in self.list_commands(ctx)
                   if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail('Too many matches: %s' % ', '.join(sorted(matches)))


@click.group(cls=AliasedGroup)
@click.option('-f', '--config-file', envvar='MV_CONF_FILE', default='./conf.json', type=click.Path(),
              help="config file location, default: ./conf.json")
@click.version_option(version=version)
@click.pass_context
def mvconf(ctx, config_file):
    """
    Create, Bind Network to each container in Service <For DCE SPD Bank>
    """
    ctx.obj = config_file


@mvconf.command(add_help_option=True)
@click.option('-u', '--username', envvar='USERNAME', prompt=True, help='Username of DCE')
@click.option('-p', '--password', envvar='PASSWORD', prompt=True, help='Password of DCE', hide_input=True)
@click.argument('url')
def login(username, password, url):
    """
    Login to DCE and save auth to ~/.dce_auth
    """
    DCEAuth.login(url, password, username).save()


@mvconf.command()
@click.pass_context
def disconnect(ctx):
    """
    Disconnect service from networks.
    """
    client, auth = get_docker_client_auth(ctx.obj)
    config = get_config(ctx.obj)
    check_config(config)
    services = config.get('services', [])
    node_clients = get_node_clients(auth.username, auth.password, client)
    for service in services:
        log.info("Disconnect service '%s' from network '%s'..." % (service.get('name'), service.get('network')))
        disconnect_service(clients=node_clients, **service)
        log.info('Disconnect service done.\n')


@mvconf.command()
@click.pass_context
def rm(ctx):
    """
    Remove networks from each node.
    """
    client, auth = get_docker_client_auth(ctx.obj)
    config = get_config(ctx.obj)
    check_config(config)
    networks = config.get('networks', [])
    node_clients = get_node_clients(auth.username, auth.password, client)

    for network in networks:
        log.info("Removing network '%s'..." % network.get('name'))
        remove_network(clients=node_clients, **network)
        log.info('Removing network done.\n')


@mvconf.command()
@click.pass_context
def up(ctx):
    """
    Create networks and connect service to it.
    """
    client, auth = get_docker_client_auth(ctx.obj)
    config = get_config(ctx.obj)
    check_config(config)
    networks = config.get('networks', [])
    services = config.get('services', [])
    node_clients = get_node_clients(auth.username, auth.password, client)
    for network in networks:
        log.info("Creating network '%s'..." % network.get('name'))
        create_network(clients=node_clients, **network)
        log.info('Creating network done.')
    for service in services:
        log.info("Connecting service '%s' to network '%s'..." % (service.get('name'), service.get('network')))
        connect_service(clients=node_clients, **service)
        log.info('Connecting service done.')


@mvconf.command()
@click.pass_context
def down(ctx):
    """
    Disconnect service from and remove networks.
    """
    ctx.forward(disconnect)
    ctx.forward(rm)


@mvconf.command()
@click.pass_context
def config(ctx):
    """
    Check config file.
    """
    print os.path.abspath(ctx.obj)
    config = get_config(ctx.obj)
    check_config(config)
    print json.dumps(config, indent=2)


@mvconf.command()
@click.pass_context
def status(ctx):
    """
    Show macvlan status.
    """
    from tabulate import tabulate

    header_map = OrderedDict([
        ('CONTAINER ID', 'id'),
        ('CONTAINER NAME', 'name'),
        ('MACVLAN IP', 'ip'),
        ('SERVICE NAME', 'service_name'),
        ('NETWORK NAME', 'network_name'),
        ('HOSTNAME', 'hostname'),
        ('HOST IP', 'host_ip'),
    ])
    client, auth = get_docker_client_auth(ctx.obj)
    node_clients = get_node_clients(auth.username, auth.password, client)
    cs = collect_macvlan_status(node_clients)
    columns = [[c.get(k) for k in header_map.values()] for c in cs]
    print(tabulate(columns, headers=header_map.keys()))


if __name__ == '__main__':
    mvconf()
