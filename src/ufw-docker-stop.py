#!/usr/bin/env python
import subprocess
from common import filter_empty, logger_init

logger = logger_init('ufw-docker-stop')

def run_command(command):
    return subprocess.run([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=True)

def stop_ufw_docker():
    awk = "'{print $2}'"
    containers = filter_empty(run_command(
        "docker ps -q -f 'label=UFW_MANAGED'"
    ).stdout.strip().split("\n"))
    logger.info(f"Cleaning UFW rule: containers {containers}")

    for item in containers:
        container_ip = run_command(
            f"docker inspect -f '{{{{range.NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' {item}"
        ).stdout.strip().split("\n")[0]

        logger.info(f"Cleaning UFW rule: container_ip {container_ip}")

        rule_num = run_command(
            f"ufw status numbered | grep {container_ip} | wc -l"
        ).stdout.strip().split("\n")[0]

        logger.info(f"Cleaning UFW rule: rule_num {rule_num}")

        rule_id = run_command(
            f"ufw status numbered | grep {container_ip} | awk -F \"[][]\" {awk} | sed -n '1p'"
        ).stdout.strip().split("\n")[0]

        logger.info(f"Cleaning UFW rule: rule_id {rule_id}")

        for _ in range(int(rule_num)):
            ufw_delete = run_command(
                f"yes y | ufw delete {rule_id}"
            ).stdout.split("\n")[1].strip()
            logger.info(f"Cleaning UFW rule: container {item} deleted rule '{ufw_delete}'")

if __name__ == '__main__':
    stop_ufw_docker()