#!/bin/bash
set -e

DAYS=30
SUBJ=/CN=localhost

openssl ecparam -name prime256v1 -genkey -param_enc named_curve -out ec-key.pem
openssl req -new -x509 -key ec-key.pem -out ec-cert.pem -days $DAYS -subj "$SUBJ"

# http://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl
openssl req -x509 -newkey rsa:2048 -keyout rsa-key.pem -out rsa-cert.pem -nodes -days $DAYS -subj "$SUBJ"

#openssl x509 -in ec-cert.pem -text -noout
