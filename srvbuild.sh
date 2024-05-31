#!/bin/env bash
# exit when any command fails
set -e

gitroot=`git rev-parse --show-toplevel`
cd $gitroot

#echo "generating server"
$gitroot/generator.sh

echo "building backend"
#CGO_LDFLAGS="-Wl,-Bstatic -ljemalloc -Wl,-Bdynamic"
#go build   -o=/dir_for_bin/client.bin cmd/mstor2-client/main.go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build  -o=$gitroot/build/server.bin $gitroot/cmd/mukade-server/main.go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build  -o=$gitroot/build/client.bin $gitroot/cmd/mukade-client/main.go