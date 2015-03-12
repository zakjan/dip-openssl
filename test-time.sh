#!/usr/bin/env sh

FILE=${1:-test-8k.dat}

apps/openssl s_time -connect 127.0.0.1:4444 -time 10 -new -www /${FILE}
