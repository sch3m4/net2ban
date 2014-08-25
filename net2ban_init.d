#! /bin/bash
#
# net2ban        Start/stop net2ban service
#

### BEGIN INIT INFO
# Provides:          net2ban
# Required-Start:    $remote_fs $network $named $time $rabbitmq-server
# Required-Stop:     $remote_fs $network $named $time $rabbitmq-server
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Starts net2ban service
# Description:       Starts net2ban, a service to remotely
#                    deploy firewall rules
### END INIT INFO

NAME='net2ban'
DAEMON="/usr/bin/python"
DIR="/usr/share/$NAME"
ACTIONS="$DIR/actions"
ARGS="$DIR/$NAME.py"
PIDFILE="/var/run/$NAME.pid"
USER="$NAME"
GROUP="$NAME"

case "$1" in
	start)
	[ -d $ACTIONS ] || mkdir -p $ACTIONS
	echo "Starting $NAME"
	/sbin/start-stop-daemon --start --pidfile $PIDFILE --user $USER --group $GROUP -b --make-pidfile --chuid $USER --chdir $DIR --exec $DAEMON $ARGS
	;;

	stop)
	echo "Stopping $NAME"
	/sbin/start-stop-daemon --stop --pidfile $PIDFILE --verbose
	rm "$PIDFILE" 2>/dev/null
	;;

	status)
	if [ -f $PIDFILE ]
	then
		echo "$NAME status: Running"
	else
		echo "$NAME status: Stopped"
	fi
	;;

	*)
	echo "Usage: /etc/init.d/$NAME {start|stop|status}"
	exit 1
	;;
esac

exit 0
