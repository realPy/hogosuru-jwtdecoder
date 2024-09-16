#!/bin/bash

cd /go/src/jwtdecode
tinygo build  --no-debug -target wasm  -o docs/jwtdecode.wasm .
cp /usr/local/tinygo/targets/wasm_exec.js docs/