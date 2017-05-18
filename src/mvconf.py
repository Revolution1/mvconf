#!/usr/bin/env python
import json
import logging
import os
import sys
from collections import OrderedDict
from os import path

import click
import coloredlogs

from docker_client import get_node_clients
from handlers import DCEAuth
from handlers import check_config
from handlers import collect_macvlan_status
from handlers import connect_service
from handlers import create_network
from handlers import disconnect_service
from handlers import get_config
from handlers import get_docker_client_auth
from handlers import reconnect_ingress
from handlers import remove_network
from utils import str2bool
from version import version

SOURCE_ROOT = path.abspath(path.dirname(__file__))

sys.path.append(SOURCE_ROOT)
debug = str2bool(os.getenv('DEBUG'), False)
log_level = logging.DEBUG if debug else logging.INFO
if debug:
    __fmt = '[%(levelname)s] - %(name)s (%(filename)s %(funcName)s %(lineno)d): %(message)s'
else:
    __fmt = '[%(levelname)s] %(message)s'
logging.basicConfig(level=log_level)
coloredlogs.install(level=log_level, fmt=__fmt)
log = logging.getLogger('mvconf.main')


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
    auth = DCEAuth.login(url, password, username)
    if auth:
        auth.save()
        print('Login success.')


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
def reingress(ctx):
    """
    Reconnect containers to ingress.
    """
    client, auth = get_docker_client_auth(ctx.obj)
    config = get_config(ctx.obj)
    check_config(config)
    services = config.get('services', [])
    node_clients = get_node_clients(auth.username, auth.password, client)
    for service in services:
        log.info("Reconnect service '%s' to network 'ingress'..." % service.get('name'))
        reconnect_ingress(clients=node_clients, **service)
        log.info('Reconnect ingress done.\n')


@mvconf.command()
@click.option('--uningress', 'uningress', flag_value=True, help="Disconnect 'ingress' network")
@click.pass_context
def up(ctx, uningress):
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
        connect_service(clients=node_clients, uningress=uningress, **service)
        log.info('Connecting service done.')


@mvconf.command()
@click.pass_context
def down(ctx):
    """
    Disconnect service from and remove networks.
    """
    ctx.forward(disconnect)
    ctx.forward(rm)
    ctx.forward(reingress)


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
@click.option('--trunc/--no-trunc', default=True, help="Do not truncate output")
@click.option('--sort', help="Field to sort by, like 'host_ip' for 'HOST IP'")
@click.option('--fields', help="Fields to display, separated by comma like 'host_ip,hostname'")
@click.pass_context
def status(ctx, trunc, sort, fields):
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
    headers = header_map.keys()
    client, auth = get_docker_client_auth(ctx.obj)
    node_clients = get_node_clients(auth.username, auth.password, client)
    cs = collect_macvlan_status(node_clients)
    columns = [[c.get(k) for k in header_map.values()] for c in cs]
    if trunc:
        columns = [[i[:20] for i in c] for c in columns]
    if sort:
        keys = header_map.keys()
        key = sort.replace('_', ' ').upper()
        if not key in keys:
            log.error("No such field as '%s'" % key)
            sys.exit(1)
        index = keys.index(key)
        columns = sorted(columns, key=lambda c: c[index])
    if fields:
        fields = [f.replace('_', ' ').replace("'", '').replace('"', '').upper() for f in fields.split(',')]
        keys = header_map.keys()
        for f in fields:
            if not f in keys:
                log.error("No such field as '%s'" % f)
                sys.exit(1)
        indexs = [keys.index(f) for f in fields]
        columns = [[c[i] for i in indexs] for c in columns]
        headers = [headers[i] for i in indexs]
    print(tabulate(columns, headers=headers))


if __name__ == '__main__':
    mvconf()
