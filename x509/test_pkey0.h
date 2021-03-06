const char* const test_pkey0 =
R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD1nlx1neS/fAFY
JWfFgobX5txlyrUGKtjb522d5oGp6zGSA1vmabIgSbPdSCCXDw5p4I2Fro3tgI6p
pQB1US7E9LEc8ZI0XadWShy00ewo+9dOBbRrspo079VjfdAmHF56X6M2id07E3aF
Tq3fijYDFzfn3+RKc0S3jS9Cqv3MIDMdzl3W6tlDroVgQjc5T6tGc8oIs7B1shZn
0vRHtSNK2fb4zSbP6/zykEOvZNX0sF1WhobXUmCrVQ+ETesWn9I2hNGUtX7QOqrI
1XJtBP7c+MKM8rOoOEQtx4bcmKv6/O/g1cMtMtb5OzxsGLdRdIruGmND1esz6SgX
tOP1j8wNAgMBAAECggEBAN1gv5svFebU4O1OwYpOjDT6mnmQy7pkUhNaMv2XrhS1
rHcbWfCCIY9ifqAai207n9UkFMqBuuBu96bF1nTnGA1jMmORBCL4qoNmxxre/kku
PC/Rin1re/vskttaoYpIFYucuaHFfsXpU/DxKlwJ2YbNnZD7xmqoHC6ILSmcrqYU
N5T/cpGB+cJIkKOSSw57YIa5aqyRBBMiyi/MTgBU0fJYj+smkxQ9/Huo7MhuEbSE
Ac1av3oInrOwWaM8uqSsmHdEOBzsqnLvlP57ln5MuAfLjG9afY4Kai8nHHeh3SHS
Rsgs3oUCnqepoNzvpOGPSWwA5TWW2SugdJ+H9gCqOi0CgYEA/LUiAh0eZhi7xY1d
+qaZ3INNv7w+MJ8SXGNg7djmbgzG5mekoyAxkKayFRdLFifsIlkaRcO1NoIbKrJr
iJ8lSImaU+8sB6+tY9R8vUdUAcCPHafsLA50l8Fpufyv9PkrpH8I46Cf0npRGPwq
bhR+X6tmJXOVCc1w/+oQ/Kffcp8CgYEA+NGVjzi3B8+tzkSk4697La3N522VnX/A
Tr8AP2vKtOHNoCaerXY62eKgLL31PV9cyGiIfqZE0sVJLZngI+M3/6QQKxAyEOVr
d/ZMcDrUzp1RcC6AxcFeJ6oUf4PwBvcAruZWVVUamef/b/VuNgZmtlAdvJdlhTqV
9LM57sOFzdMCgYBSnh1aN47irh9lfMxG0ATpdPwMPUzPtJHaJptf51OekwrL9QJ8
WmAZ/IWoI49m1PJ8YEkYmd06ztp24RIK/oy/5EzSOBVbBfJX+vY1I4axc/TWKzop
RSiVHKSmK5iTLIs6IlYTpUXbGCY/VuHAT27pdC3W/KyzIblZ0XpwP6nr3QKBgBcQ
fnefP0AnHSpgrJQ6gQWT9eE9BEBsRixGgkRevpST1dbBnbXgnsXxvv1GwoPk4hnl
rrlmujx7czQZ7nAFMPyufZ0wTCPK0HJ3T1Cb83wPkyv984vhR9QPbQUA+u/6V4Le
8SPJ1sRrf/8l1giGAWFm/cqskgmOi7X6IyWh1DZnAoGAHVzAhIfRpbR9FoBAwUcd
44orB8rwrutaF+iilJ0//LYES68iHHOKL2GobWdQcO6YoLJ86iVk181OWUprIcqP
KbseuuJOJws1XceRwASlW8fVAymw0XvmcyaqrlKVq646NjFwvQJQ6e3Z6LzpEkff
iVxeUlOsIJuDakJ0vAnrPf0=
-----END PRIVATE KEY-----)";

const char* const test_pkey0_n = // modulus
"00F59E5C759DE4BF7C01582567C58286D7E6DC65CAB5062AD8DBE76D9DE6"
"81A9EB3192035BE669B22049B3DD4820970F0E69E08D85AE8DED808EA9A5"
"0075512EC4F4B11CF192345DA7564A1CB4D1EC28FBD74E05B46BB29A34EF"
"D5637DD0261C5E7A5FA33689DD3B1376854EADDF8A36031737E7DFE44A73"
"44B78D2F42AAFDCC20331DCE5DD6EAD943AE85604237394FAB4673CA08B3"
"B075B21667D2F447B5234AD9F6F8CD26CFEBFCF29043AF64D5F4B05D5686"
"86D75260AB550F844DEB169FD23684D194B57ED03AAAC8D5726D04FEDCF8"
"C28CF2B3A838442DC786DC98ABFAFCEFE0D5C32D32D6F93B3C6C18B75174"
"8AEE1A6343D5EB33E92817B4E3F58FCC0D";
const char* const test_pkey0_e = // publicExponent
"010001"; // 65537
const char* const test_pkey0_d = // privateExponent
"00DD60BF9B2F15E6D4E0ED4EC18A4E8C34FA9A7990CBBA6452135A32FD97"
"AE14B5AC771B59F082218F627EA01A8B6D3B9FD52414CA81BAE06EF7A6C5"
"D674E7180D633263910422F8AA8366C71ADEFE492E3C2FD18A7D6B7BFBEC"
"92DB5AA18A48158B9CB9A1C57EC5E953F0F12A5C09D986CD9D90FBC66AA8"
"1C2E882D299CAEA6143794FF729181F9C24890A3924B0E7B6086B96AAC91"
"041322CA2FCC4E0054D1F2588FEB2693143DFC7BA8ECC86E11B48401CD5A"
"BF7A089EB3B059A33CBAA4AC987744381CECAA72EF94FE7B967E4CB807CB"
"8C6F5A7D8E0A6A2F271C77A1DD21D246C82CDE85029EA7A9A0DCEFA4E18F"
"496C00E53596D92BA0749F87F600AA3A2D";
const char* const test_pkey0_p = // prime1
"00FCB522021D1E6618BBC58D5DFAA699DC834DBFBC3E309F125C6360EDD8"
"E66E0CC6E667A4A3203190A6B215174B1627EC22591A45C3B536821B2AB2"
"6B889F2548899A53EF2C07AFAD63D47CBD475401C08F1DA7EC2C0E7497C1"
"69B9FCAFF4F92BA47F08E3A09FD27A5118FC2A6E147E5FAB6625739509CD"
"70FFEA10FCA7DF729F";
const char* const test_pkey0_q = // prime2
"00F8D1958F38B707CFADCE44A4E3AF7B2DADCDE76D959D7FC04EBF003F6B"
"CAB4E1CDA0269EAD763AD9E2A02CBDF53D5F5CC868887EA644D2C5492D99"
"E023E337FFA4102B103210E56B77F64C703AD4CE9D51702E80C5C15E27AA"
"147F83F006F700AEE65655551A99E7FF6FF56E360666B6501DBC9765853A"
"95F4B339EEC385CDD3";
const char* const test_pkey0_e1 = // exponent1
"529E1D5A378EE2AE1F657CCC46D004E974FC0C3D4CCFB491DA269B5FE753"
"9E930ACBF5027C5A6019FC85A8238F66D4F27C60491899DD3ACEDA76E112"
"0AFE8CBFE44CD238155B05F257FAF6352386B173F4D62B3A294528951CA4"
"A62B98932C8B3A225613A545DB18263F56E1C04F6EE9742DD6FCACB321B9"
"59D17A703FA9EBDD";
const char* const test_pkey0_e2 = // exponent2
"17107E779F3F40271D2A60AC943A810593F5E13D04406C462C4682445EBE"
"9493D5D6C19DB5E09EC5F1BEFD46C283E4E219E5AEB966BA3C7B733419EE"
"700530FCAE7D9D304C23CAD072774F509BF37C0F932BFDF38BE147D40F6D"
"0500FAEFFA5782DEF123C9D6C46B7FFF25D60886016166FDCAAC92098E8B"
"B5FA2325A1D43667";
const char* const test_pkey0_c = // coefficient
"1D5CC08487D1A5B47D168040C1471DE38A2B07CAF0AEEB5A17E8A2949D3F"
"FCB6044BAF221C738A2F61A86D675070EE98A0B27CEA2564D7CD4E594A6B"
"21CA8F29BB1EBAE24E270B355DC791C004A55BC7D50329B0D17BE67326AA"
"AE5295ABAE3A363170BD0250E9EDD9E8BCE91247DF895C5E5253AC209B83"
"6A4274BC09EB3DFD";
