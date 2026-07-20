#!/bin/bash
set -euo pipefail

# must match `user` in sandbox_config.py
USER_NAME=user

# native installer; drops the binary in ~/.local/bin for the login user
sudo -iu "$USER_NAME" sh -c 'curl -fsSL https://claude.ai/install.sh | bash'
