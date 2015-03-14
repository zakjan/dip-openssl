#!/usr/bin/env sh

apps/openssl s_server -accept 4444 -cert selfsigned.crt -key selfsigned.key -cipher DHE-RSA-CAESAR-SHA256 # -WWW
