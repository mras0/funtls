#!/bin/bash
set -e

THISDIR=$(dirname $(readlink -f $0))
CERT=$THISDIR/ec-cert.pem
KEY=$THISDIR/ec-key.pem
CERT2=$THISDIR/rsa-cert.pem
KEY2=$THISDIR/rsa-key.pem
OPENSSL=${OPENSSL=~/build/openssl-1.0.2a/}

make -C "$OPENSSL" build_libs build_apps
$DEBUG "$OPENSSL/apps/openssl" s_server $* -www -debug -trace -msg -cert "$CERT" -key "$KEY" -dcert "$CERT2" -dkey "$KEY2"
