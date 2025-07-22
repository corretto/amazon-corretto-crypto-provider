#include <openssl/digest.h>
#define DIGEST_NAME sha3_224 
#define DIGEST_LENGTH 28
#define DIGEST_BLOCK_SIZE 144
#define MD_CTX_SIZE 400
#define MD_DIGEST_SIZE 28
#include "hash_evp_template.cpp.template"