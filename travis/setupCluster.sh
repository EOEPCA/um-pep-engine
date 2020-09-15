#!/bin/bash -x

### CONFIGURATION VARIABLES
#GLUU_SECRET_ADAPTER="kubernetes"
#ADMIN_PW="admin_Abcd1234#"
#EMAIL="support@gluu.org"
DOMAIN="test.eoepca.org"
##ORG_NAME="Deimos"
#COUNTRY_CODE="PT"
#STATE="NA"
#CITY="Lisbon"
#GLUU_CONFIG_ADAPTER="kubernetes"
#LDAP_TYPE="opendj"

# Install minikube and kubectl
K8S_VER=v1.13.0
TF_VER=0.12.25
MINIKUBE_VER=v1.9.1

kubectl create cm um-pep-engine-config --from-env-file=../src/config/um-pep-engine-config-env-vars

# Apply pep-engine
echo "Applying pep-engine"
kubectl apply -f ../src/config/pep-engine-volumes.yaml
cat ../src/config/pep-engine.yaml | sed "s/{{GLUU_DOMAIN}}/$DOMAIN/g" | sed -s "s@NGINX_IP@$(minikube ip)@g" | kubectl apply -f -
echo "##### Waiting for pep-engine to start (will take around 5 minutes, ContainerCreating errors are expected):"
echo "Done!"
