#!/bin/sh

if [ ! -z ${DT_ENABLE} ]; then
	export DT_OPTARGS=Server="${DT_COLLECTOR}" Name="${DT_AGENTNAME}"
	export LD_PRELOAD=/opt/dynatrace-6.5/agent/lib64/libdtagent.so
	/etc/init.d/dynaTraceWebServerAgent start
	echo "Dynatace Web Server Agent started"
else
	echo "Dynatrace Web Server Agent disabled"
fi

nginx -g "daemon off;"