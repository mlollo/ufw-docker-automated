#! /bin/sh

### BEGIN INIT INFO
# Provides:          ufw-docker
# Required-Start:    docker ufw $local_fs $remote_fs $syslog
# Required-Stop:     docker ufw $local_fs $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start/stop ufw-docker
# Description:
# processname: ufw-docker
### END INIT INFO

PATH=/sbin:/usr/sbin:/bin:/usr/bin

. /lib/lsb/init-functions

case "$1" in
  start)
    # No-op
    /usr/lib/ufw-docker/venv/bin/python3 -u /usr/lib/ufw-docker/start.py
    ;;
  restart|reload|force-reload)
    echo "Error: argument '$1' not supported" >&2
    exit 3
    ;;
  stop)
    /usr/lib/ufw-docker/venv/bin/python3 -u /usr/lib/ufw-docker/stop.py
    ;;
  *)
    echo "Usage: $0 start|stop" >&2
    exit 3
    ;;
esac

:
