#!/bin/bash
set -euo pipefail

apt-get update
apt-get upgrade -y
apt-get install -y tmux emacs podman

# install uv for user
sudo -u user -H sh -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'
