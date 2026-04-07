#!/bin/bash
#---
# name: Discobot Auth
# description: OIDC provider and federated auth service for Discobot
# order: 2
# http: 3010
# path: /.well-known/openid-configuration
#---

set -e

exec pnpm dev:authservice
