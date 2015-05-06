#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <KeyType>"
    echo "Where KeyType is rsa/ec"
    exit 1
fi

THISDIR=$(dirname $(readlink -f $0))
CERT=$THISDIR/$1-cert.pem
KEY=$THISDIR/$1-key.pem
shift
OPENSSL=${OPENSSL=~/build/openssl-1.0.2a/}

make -C "$OPENSSL" build_libs build_apps
"$OPENSSL/apps/openssl" s_server $* -www -debug -trace -msg -cert "$CERT" -key "$KEY"
