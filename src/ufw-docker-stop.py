#!/usr/bin/env python
import subprocess
from common import filter_empty

def stop_ufw_docker():
    awk = "'{print $2}'"
    containers = filter_empty(subprocess.run(
        [f"docker ps -q -f 'label=UFW_MANAGED'"],
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        universal_newlines=True, 
        shell=True
    ).stdout.strip().split("\n"))
    print(f"ufw-docker: Cleaning UFW rule: containers {containers}")

    for item in containers:
        container_ip = subprocess.run(
            [f"docker inspect -f '{{{{range.NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' {item}"],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            universal_newlines=True, 
            shell=True
        ).stdout.strip().split("\n")[0]

        print(f"ufw-docker: Cleaning UFW rule: container_ip {container_ip}")

        rule_num = subprocess.run(
            [f"ufw status numbered | grep {container_ip} | wc -l"],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            universal_newlines=True, 
            shell=True
        ).stdout.strip().split("\n")[0]

        print(f"ufw-docker: Cleaning UFW rule: rule_num {rule_num}")

        rule_id = subprocess.run(
            [f"ufw status numbered | grep {container_ip} | awk -F \"[][]\" {awk} | sed -n '1p'"],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            universal_newlines=True, 
            shell=True
        ).stdout.strip().split("\n")[0]

        print(f"ufw-docker: Cleaning UFW rule: rule_id {rule_id}")

        for _ in range(int(rule_num)):
            ufw_delete = subprocess.run(
                [f"yes y | ufw delete {rule_id}"],
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                universal_newlines=True,
                shell=True
            ).stdout.split("\n")[1].strip()
            print(f"ufw-docker: Cleaning UFW rule: container {item} deleted rule '{ufw_delete}'")

if __name__ == '__main__':
    stop_ufw_docker()