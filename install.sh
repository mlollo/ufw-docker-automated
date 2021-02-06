#! /bin/bash
# requirement python3-venv
# Run :  sudo ./install.sh

mkdir -p /usr/lib/ufw-docker
cp ./src/requirements.txt /usr/lib/ufw-docker/requirements.txt
cp ./src/common.py /usr/lib/ufw-docker/common.py
cp ./src/ufw-docker-automated.py /usr/lib/ufw-docker/automated.py
cp ./src/ufw-docker-start.py /usr/lib/ufw-docker/start.py
cp ./src/ufw-docker-stop.py /usr/lib/ufw-docker/stop.py
cp ./src/ufw-docker-automated.service /lib/systemd/system/ufw-docker-automated.service
cp ./src/ufw-docker.sh /etc/init.d/ufw-docker
chmod 755 /etc/init.d/ufw-docker
chown root:root /etc/init.d/ufw-docker

python3 -m venv /usr/lib/ufw-docker/venv
source "/usr/lib/ufw-docker/venv/bin/activate"
pip3 install -r /usr/lib/ufw-docker/requirements.txt
deactivate

update-rc.d ufw-docker defaults
systemctl daemon-reload
systemctl enable ufw-docker-automated.service
systemctl enable ufw-docker.service
systemctl start ufw-docker-automated.service
systemctl start ufw-docker.service
