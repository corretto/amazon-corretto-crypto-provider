#include <openssl/digest.h>
#define DIGEST_NAME sha3_256 
#define DIGEST_LENGTH 32
#define DIGEST_BLOCK_SIZE 136
#define MD_CTX_SIZE 400
#define MD_DIGEST_SIZE 32
#include "hash_evp_template.cpp.template"