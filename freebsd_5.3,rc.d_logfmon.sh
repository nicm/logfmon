#!/bin/sh
#
# $Id$
#

# PROVIDE: logfmon
# REQUIRE: DAEMON
# BEFORE:  LOGIN
# KEYWORD: FreeBSD nojail

. /etc/rc.subr

name=logfmon
rcvar=`set_rcvar`

command=/usr/local/sbin/logfmon
required_files=/usr/local/etc/logfmon.conf

pidfile="/var/run/${name}.pid"

logfmon_enable=${logfmon_enable:-"NO"}
logfmon_flags=${logfmon_flags:-"-f /usr/local/etc/logfmon.conf"}

command_args="${logfmon_flags}"

load_rc_config $name
run_rc_command "$1"