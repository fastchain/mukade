#!/bin/bash
swagger generate server -A mukade -f ./swagger.yml
swagger generate client -A mukade -f ./swagger.yml