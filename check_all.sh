#!/bin/bash
set -e

supported_ciphers=\
"rsa_with_aes_128_gcm_sha256 "\
"rsa_with_aes_256_gcm_sha384 "\
"rsa_with_rc4_128_md5 "\
"rsa_with_rc4_128_sha "\
"rsa_with_3des_ede_cbc_sha "\
"rsa_with_aes_128_cbc_sha "\
"rsa_with_aes_256_cbc_sha "\
"rsa_with_aes_128_cbc_sha256 "\
"rsa_with_aes_256_cbc_sha256 "\
"rsa_with_aes_128_gcm_sha256 "\
"dhe_rsa_with_3des_ede_cbc_sha "\
"dhe_rsa_with_aes_128_cbc_sha "\
"dhe_rsa_with_aes_256_cbc_sha "\
"dhe_rsa_with_aes_128_cbc_sha256 "\
"dhe_rsa_with_aes_256_cbc_sha256 "\
"ecdhe_rsa_with_aes_128_gcm_sha256 "\
"ecdhe_rsa_with_aes_256_gcm_sha384 "\
"ecdhe_ecdsa_with_aes_128_gcm_sha256 "\
"ecdhe_ecdsa_with_aes_256_gcm_sha384 "\

uri=https://localhost:4433/
if [ -x $PWD/funtls ]; then
    builddir=$PWD
else
    builddir=$(dirname $(readlink -f $0))/build
fi

if ! [ -d $builddir ]; then
    echo $builddir directory not found
    exit 1
fi

make -C $builddir || exit $?

exe=$builddir/funtls

if ! [ -x $exe ]; then
    echo $exe executable not found
    exit 1
fi

for cs in $supported_ciphers; do
    $exe $uri $cs || exit $?
done

echo All suites tested.
