#!/bin/bash

cd /go/src/jwtdecode
tinygo build  --no-debug -target wasm  -o docs/jwtdecode.wasm .
cp /usr/local/tinygo/targets/wasm_exec.js docs/
sed -i "s@console.error('syscall\/js@//console.error('syscall/js@g" docs/wasm_exec.js
