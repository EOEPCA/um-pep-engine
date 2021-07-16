#!/bin/bash
if [ ! "$(docker ps -q -f name=mongo)" ]; then
    if [ "$(docker ps -aq -f status=exited -f name=mongo)" ]; then
        # removes old container
        docker rm mongo
    fi
    # creates new mongo container
    docker run -p 27017:27017 -d --name mongo mongo
fi