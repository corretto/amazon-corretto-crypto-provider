#include <openssl/digest.h>
#define DIGEST_NAME sha3_512
#define DIGEST_LENGTH 64
#define DIGEST_BLOCK_SIZE 72
#define MD_CTX_SIZE 400
#include "hash_evp_template.cpp.template"