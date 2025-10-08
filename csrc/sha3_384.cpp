#include <openssl/digest.h>
#define DIGEST_NAME sha3_384 
#define DIGEST_LENGTH 48
#define DIGEST_BLOCK_SIZE 104
#define MD_CTX_SIZE 400
#include "hash_evp_template.cpp.template"