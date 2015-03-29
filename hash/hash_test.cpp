#include <hash/sha.h>
#include <stdio.h>
#include <string.h>

void printhex(const void* data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", ((uint8_t*)data)[i]);
    }
    printf("\n");
}

void sha256_test(const char* expected, const char* test_data, size_t test_data_len)
{
    SHA256Context context;
    SHA256Reset(&context);
    SHA256Input(&context, (const uint8_t*)test_data, test_data_len);
    uint8_t digest[SHA256HashSize];
    SHA256Result(&context, digest);
    printf("Expecting %s\n", expected);
    printf("Result    ");
    printhex(digest, SHA256HashSize);
}

int main()
{
    sha256_test("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "", 0);
    sha256_test("936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af", "helloworld", strlen("helloworld"));
}
