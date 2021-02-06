#!/usr/bin/env python
import re
import subprocess
import os
import logging
from ipaddress import ip_network

levels = {
    'CRITICAL': logging.CRITICAL,
    'ERROR': logging.ERROR,
    'WARN': logging.WARNING,
    'WARNING': logging.WARNING,
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG
}

def logger_init(name):
    logging.basicConfig(
        level=levels.get(os.environ.get('LOG_LEVEL', 'INFO').upper()),
        format=name+'[%(threadName)-9s]: %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger(name)
    
# implementation of a get method ontop __builtins__.list class
class _list(list):
    def get(self, index, default=None):
        try:
            return self[index] if self[index] else default
        except IndexError:
            return default

def to_string_port(port):
    if port.get(0) and port.get(1):
        return f"on port {int(port.get(0))}/{port.get(1)}"
    elif port.get(0):
        return f"on port {int(port.get(0))}"
    elif port.get(1):
        return f"on proto {port.get(1)}"
    else:
        return ""

def validate_port(port):
    if not port:
        return {}
    r = re.compile(r'^(\d+)?((/|^)(tcp|udp))?$')
    if r.match(port) is None:
        raise ValueError(f"'{port}' does not appear to be a valid port and protocol (examples: '80/tcp' or 'udp')")
    if port in ['tcp', 'udp']:
        return {'protocol': port, 'to_string_port': to_string_port(_list([None, port]))}
    port_and_protocol_split = _list(port.split('/'))
    if not (1 <= int(port_and_protocol_split.get(0)) <= 65535):
        raise ValueError(f"'{port}' does not appear to be a valid port number")
    return {'port': int(port_and_protocol_split.get(0)), 'protocol': port_and_protocol_split.get(1), 'to_string_port': to_string_port(port_and_protocol_split)}

def validate_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    labels = hostname.split(".")
    # the TLD must be not all-numeric
    if re.match(r'[0-9]+$', labels[-1]):
        return False
    allowed = re.compile(r'(?!-)[A-Z\d\-_]{1,63}(?<!-)$', re.IGNORECASE)
    return all(allowed.match(x) for x in labels)

def validate_ip_network(ipnet):
    try:
        ip_network(ipnet)
        return True
    except ValueError:
        return False

# ipnet stands for ip or subnet
def validate_ipnet(ipnet):
    if not ipnet:
        return [{}]
    elif ipnet == "any":
        return [{'ipnet': "any"}]
    elif not validate_ip_network(ipnet=ipnet) and validate_hostname(hostname=ipnet):
        host_output = subprocess.run([f"host -t a {ipnet}"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                shell=True).stdout.strip().split("\n")
        if "not found:" in _list(host_output).get(0, ''):
            print(f"ufw-docker-automated: Warning UFW label: {host_output[0]}")
        return [{'ipnet': ip_network(_list(line.split("has address")).get(1).strip())} for line in host_output if _list(line.split("has address")).get(1)]
    else:
        return [{'ipnet': ip_network(ipnet)}]

def parse_ufw_allow_to(label):
    output = []
    for item in label.split(';'):
        item_list = _list(item.split(':'))
        if len(item_list) == 2 or len(item_list) == 1:
            ipnet_list = validate_ipnet(ipnet=item_list.get(0))
            port = validate_port(port=item_list.get(1))
            output += [{**ipnet, **port} for ipnet in ipnet_list if ipnet]
    return output

def parse_ufw_allow_from(label):
    return [ip_network(ipnet) for ipnet in label.split(';') if ipnet]

def filter_empty(items):
    return [item for item in items if item]
