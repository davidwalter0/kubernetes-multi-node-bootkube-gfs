#!/bin/bash
export APPL=ssh
export CORE_USER=core
export DOCKER_USER=davidwalter
export IMAGE=systemd-ssh:testing
export LOAD_BALANCER_IP=192.168.0.200
export PRIVATE_KEY_FILE=${HOME}/.ssh/id_ed25519
export PRIVATE_KEY_FILE_NAME=id_ed25519
export PUBLIC_KEY_FILE=${HOME}/.ssh/id_ed25519.pub
export PUBLIC_KEY_FILE_NAME=id_ed25519.pub
export RELEASE=testing

${GOPATH}/bin/applytmpl < templates/deployment-ssh-jump-server.yaml.tmpl > cluster/manifests/deployment-ssh-jump-server.yaml
