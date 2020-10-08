[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
![Build][build-shield]

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/EOEPCA/um-pep-engine">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">um-pep-engine</h3>

  <p align="center">
    Policy Enforcement Point for EOEPCA project
    <br />
    <a href="https://eoepca.github.io/um-pep-engine/"><strong>Explore the docs »</strong></a>
    <br />
    <a href="https://github.com/EOEPCA/um-pep-engine/issues">Report Bug</a>
    ·
    <a href="https://github.com/EOEPCA/um-pep-engine/issues">Request Feature</a>
  </p>
</p>

## Table of Contents

- [Table of Contents](#table-of-contents)
  - [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Dependencies](#dependencies)
- [Configuration](#configuration)
- [Usage & functionality](#usage--functionality)
- [Developer documentation](#developer-documentation)
  - [Demo functionality](#demo-functionality)
  - [Test functionality](#test-functionality)
  - [Endpoints](#endpoints)
  - [Resources Repository](#resources-repository)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Acknowledgements](#acknowledgements)

<!-- ABOUT THE PROJECT -->

### Built With

- [Python](https://www.python.org//)
- [YAML](https://yaml.org/)
- [Travis CI](https://travis-ci.com/)
- [Docker](https://docker.com)
- [Kubernetes](https://kubernetes.io)

<!-- GETTING STARTED -->

## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

This is an example of how to list things you need to use the software and how to install them.

- [Docker](https://www.docker.com/)
- [Python](https://www.python.org//)

### Installation

1. Get into EOEPCA's development environment

```sh
vagrant ssh
```

3. Clone the repo

```sh
git clone https://github.com/EOEPCA/um-pep-engine.git
```

4. Change local directory

```sh
cd um-pep-engine
```
## Dependencies
The PEP is written and tested for python 3.6.9, and has all dependencies listed in src/requirements.txt

## Configuration

The PEP gets all its configuration from the file located under `config/config.json`.
The parameters that are accepted, and their meaning, are as follows:
- **realm**: 'realm' parameter answered for each UMA ticket. Default is "eoepca"
- **auth_server_url**: complete url (with "https") of the Authorization server.
- **proxy_endpoint**: "/path"-formatted string to indicate where the reverse proxy should listen. The proxy will catch any request that starts with that path. Default is "/pep"
- **service_host**: Host for the proxy to listen on. For example, "0.0.0.0" will listen on all interfaces
- **service_port**: Port for the proxy to listen on. By default, **5566**. Keep in mind you will have to edit the docker file and/or kubernetes yaml file in order for all the prot forwarding to work.
- **s_margin_rpt_valid**: An integer representing how many seconds of "margin" do we want when checking RPT. For example, using **5** will make sure the provided RPT is valid now AND AT LEAST in the next 5 seconds.
- **check_ssl_certs**: Toggle on/off (bool) to check certificates in all requests. This should be forced to True in a production environment
- **use_threads**: Toggle on/off (bool) the usage of threads for the proxy. Recommended to be left as True.
- **debug_mode**: Toggle on/off (bool) a debug mode of Flask. In a production environment, this should be false.
- **resource_server_endpoint**: Complete url (with "https" and any port) of the Resource Server to protect with this PEP.
- **rpt_limit_uses**: Number of uses for each of the RPTs.
- **client_id**: string indicating a client_id for an already registered and configured client. **This parameter is optional**. When not supplied, the PEP will generate a new client for itself and store it in this key inside the JSON.
- **client_secret**: string indicating the client secret for the client_id. **This parameter is optional**. When not supplied, the PEP will generate a new client for itself and store it in this key inside the JSON.

## Usage & functionality

Use directly from docker with
```sh
docker run --publish <configured-port>:<configured-port> <docker image>
```
Where **configured-port** is the port configured inside the config.json file inside the image. The default image is called **eoepca/um-pep-engine:latest**.

If this is running in a development environment without proper DNS setup, add the following to your docker run command:
```sh
--add-host <auth-server-dns>:<your-ip>
```

When launched, the PEP will answer to all requests that start with the configured path. These answers will come in the form of UUMA tickets (if there are no RPT provided, or an invalid one is used).
In case the request is accompained by an "Authorization: Bearer <valid_RPT>", the PEP will make a request to the resource server, for the resource located exactly at the path requested (minus the configured at config), and return the resource's server answer.

Examples, given the example values of:
- path configured: "/pep"
- PEP is at pep.domain.com/pep
- Resource server is at remote.server.com

| Token | Request to PEP | PEP Action | PEP answer |
|-------|---------|------------|--------------|
| No RPT | pep.domain.com | None (request does not get to PEP endpoint) | None (the PEP doesn't see this request) |
| No RPT | pep.domain.com/pep/thing | Generate ticket for "/thing" | 401 + ticket |
| Valid RPT for "/thing" | pep.domain.com/pep/thing | Request to remote.server.com/thing | Contents of remote.server.com/thing |
| Valid RPT for "/thing" | pep.domain.com/pep/different | Generate ticket for "/different" | 401 + ticket |
| INVALID RPT for "/thing" | pep.domain.com/pep/thing | Generate ticket for "/thing" | 401 + ticket |
| No RPT | pep.domain.com/pep/thing/with/large/path | Generate ticket for "/thing/with/large/path" | 401 + ticket |
| Valid RPT for "/thing/with/large/path" | pep.domain.com/pep/thing/with/large/path | Request to remote.server.com/thing/with/large/path | Contents of remote.server.com/thing/with/large/path |

## Developer documentation

The API will expose an endpoint to interact with the resources.
The main endpoints for the resource operations exposed by the API are now secured with OAuth/OIDC, it would accept both OAuth and JWT in order to authorize the user and both are expected on the header.
This check will retrieve the UUID for the user and insert it on the data model of the resource storage, so when any call is made against a resource, the API will double check if the UUID of the requester matches the one associated to the resource in order to operate against it.

--------

Testing and Demo for the validation with OAuth/OIDC:

Execute the `test_validation_token.py` in `um-pep-engine/tests/`

### Demo functionality

At the moment, the PEP will auto register a resource for the sake of demoing it's capabilities, using the `create` function of the UMA handler. This can be deleted if unwanted, or expanded to dinamically register resources. Note that the UMA library used allows for full control over resources (create, delete, etc) and could be used to help in that functionality expansion.

### Test functionality

In order to test the PEP engine at the moment first you have reach this prerequisites:

- Register a client and a user inside the gluu instance and update the test_settings.json
- Disable current UMA Policies and set inside JSONConfig > OxAuth umaGrantAccessIfNoPolicies to true

### Endpoints

The PEP uses the following endpoints from a "Well Known Handler", which parses the Auth server's "well-known" endpoints:

- OIDC_TOKEN_ENDPOINT
- UMA_V2_RESOURCE_REGISTRATION_ENDPOINT
- UMA_V2_PERMISSION_ENDPOINT
- UMA_V2_INTROSPECTION_ENDPOIN

### Resources Repository


When a resource is registered, the name and id are stored as a document into a Mongodb database as a sidecar container sharing data through a persistent storage volume.
The pod runs the pep-engine image and the mongo image exposing the default mongo port (27017) where communicates the service and keeps it alive for the pep-engine container to query the database.

A local MongoDB service can be used to test the repo since the main script would listen the port 27017

## Roadmap

See the [open issues](https://github.com/EOEPCA/um-pep-engine/issues) for a list of proposed features (and known issues).


## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the Apache-2.0 License. See `LICENSE` for more information.

## Contact

[EOEPCA mailbox](eoepca.systemteam@telespazio.com)

Project Link: [https://github.com/EOEPCA/um-pep-engine](https://github.com/EOEPCA/um-pep-engine)

## Acknowledgements

- README.md is based on [this template](https://github.com/othneildrew/Best-README-Template) by [Othneil Drew](https://github.com/othneildrew).


[contributors-shield]: https://img.shields.io/github/contributors/EOEPCA/um-pep-engine.svg?style=flat-square
[contributors-url]: https://github.com/EOEPCA/um-pep-engine/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/EOEPCA/um-pep-engine.svg?style=flat-square
[forks-url]: https://github.com/EOEPCA/um-pep-engine/network/members
[stars-shield]: https://img.shields.io/github/stars/EOEPCA/um-pep-engine.svg?style=flat-square
[stars-url]: https://github.com/EOEPCA/um-pep-engine/stargazers
[issues-shield]: https://img.shields.io/github/issues/EOEPCA/um-pep-engine.svg?style=flat-square
[issues-url]: https://github.com/EOEPCA/um-pep-engine/issues
[license-shield]: https://img.shields.io/github/license/EOEPCA/um-pep-engine.svg?style=flat-square
[license-url]: https://github.com/EOEPCA/um-pep-engine/blob/master/LICENSE
[build-shield]: https://www.travis-ci.com/EOEPCA/um-pep-engine.svg?branch=master
