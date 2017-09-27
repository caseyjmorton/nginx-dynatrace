FROM nginx:1.10.3

RUN apt-get update && \
	apt-get -y install wget procps file gdb elfutils binutils bc locales nginx-dbg=1.10.3-1~jessie

# Download and install dynatrace
RUN wget https://files.dynatrace.com/downloads/OnPrem/dynaTrace/6.5/6.5.0.1289/dynatrace-wsagent-6.5.0.1289-linux-x86-64.tar -P /tmp && \
	tar -xvf /tmp/dynatrace-wsagent-6.5.0.1289-linux-x86-64.tar -C /tmp && \
	cd opt && \
	/tmp/dynatrace-wsagent-6.5.0.1289-linux-x64.sh && \
	rm -rf /tmp/* && \
	cd .. && \
	cp /opt/dynatrace-6.5/init.d/dynaTraceWebServerAgent /etc/init.d/

ADD docker_entrypoint.sh /
RUN chmod +x docker_entrypoint.sh

ENTRYPOINT "/docker_entrypoint.sh"