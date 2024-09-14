#!/bin/bash

WASM_HEADLESS=off GOOS=js GOARCH=wasm  go build -ldflags="-s -w" -o docs/jwtdecode.wasm
cp -r css docs/
cp main.html docs/

cp $(go env GOROOT)/misc/wasm/wasm_exec.js docs/