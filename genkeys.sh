#!/bin/bash

# http://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl
# http://security.stackexchange.com/questions/44251/openssl-generate-different-type-of-self-signed-certificate

# openssl ecparam -genkey -out key.pem -name prime256v1

DAYS=30
SUBJ="/CN=localhost"

case "$1" in
    ec)
        openssl ecparam -out ecparam.pem -name prime256v1
        openssl genpkey -paramfile ecparam.pem -out key.pem
        openssl req -x509 -new -days 1000 -key key.pem -out cert.pem -subj $SUBJ -days $DAYS
        rm ecparam.pem
        ;;
    *)
        openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -subj $SUBJ -days $DAYS -nodes
        ;;
 esac

