#!/usr/bin/env bash

ORIG_DIR="$(pwd)"
cd "$(dirname "$0")"
BIN_DIR="$(pwd)"

trap "cd '${ORIG_DIR}'" EXIT

# Work in the docs/ directory
cd "${BIN_DIR}/.."


for doc in SDD ICD; do
    cd $doc
	# Set context dependant on whether this script has been invoked by Travis or not
	if [ "${TRAVIS}" = "true" ]
	then
	  echo "Running in Travis..."
	else
	  # Running locally we want to remove the docker containers
	  export DOCKER_RM="--rm"
	fi
	export DOCKER_RM="--rm"
	# Prepare output/ directory
	rm -rf output
	mkdir -p output
	cp -r images output
	cp -r stylesheets output

	# Docuemnt Generation - using asciidoctor docker image
	#
	# HTML version
	docker run ${DOCKER_RM} -v $PWD:/documents/ --name asciidoc-to-html-um asciidoctor/docker-asciidoctor asciidoctor -r asciidoctor-diagram -D /documents/output index.adoc
	# PDF version
	docker run ${DOCKER_RM} -v $PWD:/documents/ --name asciidoc-to-pdf-um asciidoctor/docker-asciidoctor asciidoctor-pdf -r asciidoctor-diagram -D /documents/output index.adoc
	cd "${BIN_DIR}/.."
done 