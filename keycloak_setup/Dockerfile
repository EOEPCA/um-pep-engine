# run keycloak-setup to configure Keycloak
FROM python:alpine
WORKDIR /app
COPY keycloak_setup/ keycloak_setup/
COPY utils/ keycloak_setup/src/utils/
RUN pip install -r keycloak_setup/requirements.txt
RUN python keycloak_setup/src/main.py
