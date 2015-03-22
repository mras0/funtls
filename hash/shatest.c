#include "sha.h"
#include <stdio.h>

int main()
{
    SHA256Context context;
    SHA256Reset(&context);
    const char* test_data = "helloworld";
    SHA256Input(&context, (const uint8_t*)test_data, sizeof(test_data)-1);
    uint8_t digest[SHA256HashSize];
    SHA256Result(&context, digest);
    printf("Expecting 936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af\n");

    for (int i = 0; i < SHA256HashSize; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}
