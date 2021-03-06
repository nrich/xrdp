#!/bin/sh -e
#
# start/stop xrdp and sesman daemons
#
### BEGIN INIT INFO
# Provides:          xrdp
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start xrdp and sesman daemons
# Description:       XRDP uses the Remote Desktop Protocol to present a
#                    graphical login to a remote client allowing connection
#                    to a VNC server or another RDP server.
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/xrdp
PIDDIR=/var/run/xrdp
USERID=xrdp
RSAKEYS=/etc/xrdp/rsakeys.ini
NAME=xrdp
DESC="Remote Desktop Protocol server"
XRDP_LOG=/var/log/xrdp.log
SESMAN_LOG=/var/log/xrdp-sesman.log

test -x $DAEMON || exit 0

. /lib/lsb/init-functions

check_root()  {
    if [ "$(id -u)" != "0" ]; then
        log_failure_msg "You must be root to start, stop or restart $NAME."
        exit 4
    fi
}

if [ -r /etc/default/$NAME ]; then
   . /etc/default/$NAME
fi

# Tasks that can only be run as root
if [ "$(id -u)" = "0" ]; then
    # Check for pid dir
    if [ ! -d $PIDDIR ] ; then
        mkdir $PIDDIR
    fi
    chown $USERID:$USERID $PIDDIR

    test -f $XRDP_LOG || touch $XRDP_LOG
    test -f $SESMAN_LOG || touch $SESMAN_LOG

    chown $USERID:$USERID $XRDP_LOG
    chown $USERID:$USERID $SESMAN_LOG

    # Check for rsa key 
    if [ ! -f $RSAKEYS ] || cmp $RSAKEYS /usr/share/doc/xrdp/rsakeys.ini > /dev/null; then
        log_action_begin_msg "Generating xrdp RSA keys..."
        (umask 077 ; xrdp-keygen xrdp $RSAKEYS)
        chown $USERID:$USERID $RSAKEYS
        if [ ! -f $RSAKEYS ] ; then
            log_action_end_msg 1 "could not create $RSAKEYS"
            exit 1
        fi
        log_action_end_msg 0 "done"
    fi
fi


case "$1" in
  start)
        check_root
        exitval=0
        log_daemon_msg "Starting $DESC " 
        if pidofproc -p $PIDDIR/$NAME.pid $DAEMON > /dev/null; then
            log_progress_msg "$NAME apparently already running"
            log_end_msg 0
            exit 0
        fi
        log_progress_msg $NAME
        start-stop-daemon --start --quiet --oknodo  --pidfile $PIDDIR/$NAME.pid \
	    --chuid $USERID:$USERID --exec $DAEMON
        exitval=$?
	if [ "$SESMAN_START" = "yes" ] ; then
            log_progress_msg "sesman"
            start-stop-daemon --start --quiet --oknodo --pidfile $PIDDIR/xrdp-sesman.pid \
	       --exec /usr/sbin/xrdp-sesman
            value=$?
            [ $value -gt 0 ] && exitval=$value
        fi
        # Make pidfile readables for all users (for status to work)
        [ -e $PIDDIR/xrdp-sesman.pid ] && chmod 0644 $PIDDIR/xrdp-sesman.pid
        [ -e $PIDDIR/$NAME.pid ] && chmod 0644 $PIDDIR/$NAME.pid
        # Note: Unfortunately, xrdp currently takes too long to create
        # the pidffile unless properly patched
        log_end_msg $exitval
	;;
  stop)
        check_root
	[ -n "$XRDP_UPGRADE" -a "$RESTART_ON_UPGRADE" = "no" ] && {
	    echo "Upgrade in progress, no restart of xrdp."
	    exit 0
	}
        exitval=0
        log_daemon_msg "Stopping RDP Session manager " 
        log_progress_msg "sesman"
        if pidofproc -p  $PIDDIR/xrdp-sesman.pid /usr/sbin/xrdp-sesman  > /dev/null; then
            start-stop-daemon --stop --quiet --oknodo --pidfile $PIDDIR/xrdp-sesman.pid \
                --chuid $USERID:$USERID --exec /usr/sbin/xrdp-sesman
            exitval=$?
        else
            log_progress_msg "apparently not running"
        fi
        log_progress_msg $NAME
        if pidofproc -p  $PIDDIR/$NAME.pid $DAEMON  > /dev/null; then
            start-stop-daemon --stop --quiet --oknodo --pidfile $PIDDIR/$NAME.pid \
	    --exec $DAEMON
            value=$?
            [ $value -gt 0 ] && exitval=$value
        else
            log_progress_msg "apparently not running"
        fi
        log_end_msg $exitval
	;;
  restart|force-reload)
        check_root
	$0 stop
        # Wait for things to settle down
        sleep 1
	$0 start
	;;
  reload)
        log_warning_msg "Reloading $NAME daemon: not implemented, as the daemon"
        log_warning_msg "cannot re-read the config file (use restart)."
        ;;
  status)
        exitval=0
        log_daemon_msg "Checking status of $DESC" "$NAME"
        if pidofproc -p  $PIDDIR/$NAME.pid $DAEMON  > /dev/null; then
            log_progress_msg "running"
            log_end_msg 0
        else
            log_progress_msg "apparently not running"
            log_end_msg 1 || true
            exitval=1
        fi
	if [ "$SESMAN_START" = "yes" ] ; then
            log_daemon_msg "Checking status of RDP Session Manager" "sesman"
            if pidofproc -p  $PIDDIR/xrdp-sesman.pid /usr/sbin/xrdp-sesman  > /dev/null; then
                log_progress_msg "running"
                log_end_msg 0
            else
                log_progress_msg "apparently not running"
                log_end_msg 1 || true
                exitval=1
            fi
        fi
        exit $exitval
        ;;
  *)
	N=/etc/init.d/$NAME
	echo "Usage: $N {start|stop|restart|force-reload|status}" >&2
	exit 1
	;;
esac

exit 0
