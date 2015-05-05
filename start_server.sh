#!/bin/bash
set -e

THISDIR=$(dirname $(readlink -f $0))
CERT=$THISDIR/cert.pem
KEY=$THISDIR/key.pem
OPENSSL=${OPENSSL=~/build/openssl-1.0.2a/}

make -C "$OPENSSL" build_libs build_apps
"$OPENSSL/apps/openssl" s_server -www -debug -trace -msg -cert "$CERT" -key "$KEY"
