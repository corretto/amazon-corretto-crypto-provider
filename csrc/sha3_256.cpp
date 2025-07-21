#include <openssl/digest.h>
#define DIGEST_NAME sha3_256 
#define DIGEST_LENGTH 32
#define DIGEST_BLOCK_SIZE 136
#include "hash_evp_template.cpp.template"