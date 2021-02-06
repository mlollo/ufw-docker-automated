#!/usr/bin/env python
import json
import subprocess

from common import (logger_init, filter_empty, parse_ufw_allow_from, parse_ufw_allow_to,
                    to_string_port)

logger = logger_init('ufw-docker-start')

def run_command(command):
    return subprocess.run([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=True)

def start_ufw_docker():
    containers = filter_empty(
        run_command("docker ps -q -f 'label=UFW_MANAGED'").stdout.strip().split("\n")
    )

    for item in containers:
        container_ip = run_command(
            f"docker inspect -f '{{{{range.NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' {item}"
        ).stdout.strip().split("\n")[0]

        container_name = run_command(
            f"docker inspect -f '{{{{.Name}}}}' {item}"
        ).stdout.strip().split("\n")[0][1:]

        container_port_dict = json.loads(run_command(
            f"docker inspect -f '{{{{json .NetworkSettings.Ports}}}}' {item}"
        ).stdout.strip().split("\n")[0]).items()

        labels = json.loads(run_command(
            f"docker inspect -f '{{{{json .Config.Labels}}}}' {item}"
        ).stdout.strip().split("\n")[0])

        if 'UFW_ALLOW_FROM' in labels:
            try:
                ufw_allow_from = parse_ufw_allow_from(labels.get('UFW_ALLOW_FROM'))
            except ValueError as e:
                logger.info(f"Invalid UFW label: UFW_ALLOW_FROM={labels.get('UFW_ALLOW_FROM')} exception={e}")
                ufw_allow_from = None
                pass

        if 'UFW_DENY_OUTGOING' in labels:
            ufw_deny_outgoing = labels.get('UFW_DENY_OUTGOING').capitalize()

        if ufw_deny_outgoing == 'True' and 'UFW_ALLOW_TO' in labels:
            try:
                ufw_allow_to = parse_ufw_allow_to(labels.get('UFW_ALLOW_TO'))
            except ValueError as e:
                logger.info(f"Invalid UFW label: UFW_ALLOW_TO={labels.get('UFW_ALLOW_TO')} exception={e}")
                ufw_allow_to = None
                pass

        for key, value in container_port_dict:
            if value and ufw_allow_from:
                container_port_num = list(key.split("/"))[0]
                container_port_protocol = list(key.split("/"))[1]
                for source in ufw_allow_from:
                    # Allow incomming requests from whitelisted IPs or Subnets to the container
                    logger.info(f"Adding UFW rule: allow from {source} to container {container_name} on port {container_port_num}/{container_port_protocol}")
                    run_command(
                        f"ufw route allow proto {container_port_protocol} \
                        from {source} \
                        to {container_ip} port {container_port_num}"
                    )
                    if ufw_deny_outgoing == 'True':
                        # Allow the container to reply back to the client (if outgoing requests are denied by default)
                        logger.info(f"Adding UFW rule: allow reply from container {container_name} on port {container_port_num}/{container_port_protocol} to {source}")
                        run_command(
                            f"ufw route allow proto {container_port_protocol} \
                            from {container_ip} port {container_port_num} \
                            to {source}"
                        )

        if ufw_deny_outgoing == 'True':
            if ufw_allow_to:
                for destination in ufw_allow_to:
                    # Allow outgoing requests from the container to whitelisted IPs or Subnets
                    logger.info(f"Adding UFW rule: allow outgoing from container {container_name} to {destination.get('ipnet')} {destination.get('to_string_port', '')}")
                    destination_port = f"port {destination.get('port')}" if destination.get('port') else ""
                    destination_protocol = f"proto {destination.get('protocol')}" if destination.get('protocol') else ""
                    run_command(
                        f"ufw route allow {destination_protocol} \
                        from {container_ip} \
                        to {destination.get('ipnet')} {destination_port}"
                    )
            # Deny any other outgoing requests
            logger.info(f"Adding UFW rule: deny outgoing from container {container_name} to any")
            run_command(f"ufw route deny from {container_ip} to any")

if __name__ == '__main__':
    start_ufw_docker()
