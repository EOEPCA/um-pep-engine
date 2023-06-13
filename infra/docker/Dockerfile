# Base container
FROM python:3.8

COPY ../../requirements.txt /

RUN pip install -r requirements.txt

# Add requirements, code
COPY ../../src /

RUN ln -sf /scripts/management_tools_script.sh /bin/management_tools
RUN chmod +x /scripts/management_tools_script.sh

# Declare and expose service listening port
EXPOSE 5566/tcp
EXPOSE 5576/tcp

# Declare entrypoint of that exposed service
ENTRYPOINT ["python3", "./main.py"]
