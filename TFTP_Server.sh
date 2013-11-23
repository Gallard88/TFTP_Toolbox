#!/bin/bash
# Provides:          TFTP_Server
# Required-Start:    $syslog
# Required-Stop:     $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Example TFTP_Server
# Description:       Start/Stops TFTP Server

start() {
  # Start TFTP Server
  /usr/local/bin/TFTP_Server /opt/
}

stop() {
  # Stop TFTP_Server
  pkill TFTP_Server
}

case "$1" in 
    start)
        start
        ;;
    stop)
        stop
        ;;
    retart)
        stop
        start
        ;;
    *)
echo "Usage: $0 {start|stop|restart}"
esac
exit 0
