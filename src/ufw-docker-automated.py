#!/usr/bin/env python
import subprocess
import docker
import threading

from common import (_list, logger_init, parse_ufw_allow_from, parse_ufw_allow_to,
                    to_string_port, validate_hostname, validate_ip_network,
                    validate_ipnet, validate_port)

client = docker.from_env()
_lock = threading.Lock()
logger = logger_init('ufw-docker-automated')

def run_ufw_command(command):
    _lock.acquire()
    logger.debug(f"child thread acquired lock")
    result = subprocess.run([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=True)
    logger.debug(f"child thread releasing lock")
    _lock.release()
    return result

def handle_ufw_rules(event_type, container):
    logger.debug(f"child thread handling container {container.name}...")
    container_network = container.attrs['HostConfig']['NetworkMode']
    container_ip = None
    ufw_managed = None
    ufw_allow_from = ["any"]
    ufw_deny_outgoing = None
    ufw_allow_to = None

    container_port_dict = container.attrs['NetworkSettings']['Ports'].items()

    if container_network != 'default':
        # compose network
        container_ip = container.attrs['NetworkSettings']['Networks'][container_network]['IPAddress']
    else:
        # default network
        container_ip = container.attrs['NetworkSettings']['Networks']['bridge']['IPAddress']

    if 'UFW_MANAGED' in container.labels:
        ufw_managed = container.labels.get('UFW_MANAGED').capitalize()

    if ufw_managed == 'True':
        if 'UFW_ALLOW_FROM' in container.labels:
            try:
                ufw_allow_from = parse_ufw_allow_from(container.labels.get('UFW_ALLOW_FROM'))
            except ValueError as e:
                logger.info(f"Invalid UFW label: UFW_ALLOW_FROM={container.labels.get('UFW_ALLOW_FROM')} exception={e}")
                ufw_allow_from = None
                pass

        if 'UFW_DENY_OUTGOING' in container.labels:
            ufw_deny_outgoing = container.labels.get('UFW_DENY_OUTGOING').capitalize()

        if ufw_deny_outgoing == 'True' and 'UFW_ALLOW_TO' in container.labels:
            try:
                ufw_allow_to = parse_ufw_allow_to(container.labels.get('UFW_ALLOW_TO'))
            except ValueError as e:
                logger.info(f"Invalid UFW label: UFW_ALLOW_TO={container.labels.get('UFW_ALLOW_TO')} exception={e}")
                ufw_allow_to = None
                pass

    if event_type == 'start' and ufw_managed == 'True':
        for key, value in container_port_dict:
            if value and ufw_allow_from:
                container_port_num = list(key.split("/"))[0]
                container_port_protocol = list(key.split("/"))[1]
                for source in ufw_allow_from:
                    # Allow incomming requests from whitelisted IPs or Subnets to the container
                    logger.info(f"Adding UFW rule: allow from {source} to container {container.name} on port {container_port_num}/{container_port_protocol}")
                    run_ufw_command(
                        f"ufw route allow proto {container_port_protocol} \
                        from {source} \
                        to {container_ip} port {container_port_num}"
                    )
                    if ufw_deny_outgoing == 'True':
                        # Allow the container to reply back to the client (if outgoing requests are denied by default)
                        logger.info(f"Adding UFW rule: allow reply from container {container.name} on port {container_port_num}/{container_port_protocol} to {source}")
                        run_ufw_command(
                            f"ufw route allow proto {container_port_protocol} \
                            from {container_ip} port {container_port_num} \
                            to {source}"
                        )

        if ufw_deny_outgoing == 'True':
            if ufw_allow_to:
                for destination in ufw_allow_to:
                    # Allow outgoing requests from the container to whitelisted IPs or Subnets
                    logger.info(f"Adding UFW rule: allow outgoing from container {container.name} to {destination.get('ipnet')} {destination.get('to_string_port', '')}")
                    destination_port = f"port {destination.get('port')}" if destination.get('port') else ""
                    destination_protocol = f"proto {destination.get('protocol')}" if destination.get('protocol') else ""
                    run_ufw_command(
                        f"ufw route allow {destination_protocol} \
                        from {container_ip} \
                        to {destination.get('ipnet')} {destination_port}"
                    )
            # Deny any other outgoing requests
            logger.info(f"Adding UFW rule: deny outgoing from container {container.name} to any")
            run_ufw_command(f"ufw route deny from {container_ip} to any")

    if event_type == 'kill' and ufw_managed == 'True':
        ufw_length = run_ufw_command(f"ufw status numbered | grep {container_ip} | wc -l")
        num = ufw_length.stdout.strip().split('\n')[0]
        logger.info(f"start cleaning {num} rules")

        for _ in range(int(ufw_length.stdout.strip().split("\n")[0])):
            awk = "'{print $2}'"
            ufw_status = run_ufw_command(f"ufw status numbered | grep {container_ip} | awk -F \"[][]\" {awk} ")

            # Removing any ufw rules that contains the container ip in it
            ufw_num = ufw_status.stdout.strip().split("\n")[0]
            ufw_delete = run_ufw_command(f"yes y | ufw delete {ufw_num}")
            ufw_delete_result = ufw_delete.stdout.split("\n")[1].strip()
            logger.info(f"Cleaning UFW rule: container {container.name} deleted rule '{ufw_delete_result}'")
    logger.debug(f"child thread exiting.")

def manage_ufw():
    for event in client.events(decode=True):
        event_type = event.get('status')

        # container network is attached on start or stop event
        if event_type == 'start' or event_type == 'kill':
            container = None
            try:
                container = client.containers.get(event['id'])
            except docker.errors.NotFound as _:
                continue
            if container:
                thread = threading.Thread(target=handle_ufw_rules, args=(event_type,container,))
                logger.debug(f"starting child thread {thread.getName()} to handle container {container.name}")
                thread.start()

if __name__ == '__main__':
    manage_ufw()
