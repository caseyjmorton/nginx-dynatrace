#!/bin/sh

if [ "${DT_ENABLE}" = "TRUE" ]; then
	export DT_OPTARGS=Server=${DT_COLLECTOR},Name=${DT_AGENTNAME},ConsolelLogLevel=fine
	export LD_PRELOAD=/opt/dynatrace-6.5/agent/lib64/libdtagent.so
	/etc/init.d/dynaTraceWebServerAgent start
	echo "Dynatace Web Server Agent started"
else
	echo "Dynatrace Web Server Agent disabled"
fi

echo "Starting Nginx"
nginx -g "daemon off;" 