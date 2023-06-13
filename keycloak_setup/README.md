# Keycloak setup

Python script to setup Keycloak.

- Registers default users
- Registers needed clients
- Registers default resources

### Build and Execute

```shell
docker build -f keycloak_setup/Dockerfile . -t keycloak_setup
docker run --rm -d --name keycloak_setup keycloak_setup
```
