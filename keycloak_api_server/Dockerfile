FROM python:alpine
WORKDIR /app
COPY keycloak_api_server/conf conf
COPY keycloak_api_server/src src
COPY keycloak_api_server/requirements.txt requirements.txt
COPY utils/ src/utils/
RUN pip install -r requirements.txt
EXPOSE 5566
CMD [ "python", "-m" , "flask", "run", "--host=0.0.0.0"]
