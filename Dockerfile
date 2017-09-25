FROM nginx

RUN apt-get update && \
	apt-get -y install wget procps

# Download and install dynatrace
RUN wget https://files.dynatrace.com/downloads/OnPrem/dynaTrace/6.5/6.5.0.1289/dynatrace-wsagent-6.5.0.1289-linux-x86-64.tar -P /tmp && \
	tar -xvf /tmp/dynatrace-wsagent-6.5.0.1289-linux-x86-64.tar -C /tmp && \
	cd opt && \
	/tmp/dynatrace-wsagent-6.5.0.1289-linux-x64.sh && \
	rm -rf /tmp/* && \
	cd .. && \
	cp /opt/dynatrace-6.5/init.d/dynaTraceWebServerAgent /etc/init.d/

EXPOSE 80

ADD docker_entrypoint.sh /
RUN chmod +x docker_entrypoint.sh

CMD "/docker_entrypoint.sh"