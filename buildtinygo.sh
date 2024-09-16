#!/bin/bash

docker run --rm -v $PWD:/go/src/jwtdecode tinygo/tinygo /go/src/jwtdecode/tinygobuilder.sh