#!/usr/bin/env sh

apps/openssl s_server -accept 4433 -cert selfsigned.crt -key selfsigned.key -cipher CAESAR
