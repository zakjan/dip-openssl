#!/usr/bin/env sh

apps/openssl s_client -connect 127.0.0.1:4444 -cipher DHE-RSA-CAESAR-SHA256
