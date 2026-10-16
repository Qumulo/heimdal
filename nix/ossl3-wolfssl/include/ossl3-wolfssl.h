/*
 * The OpenSSL 3 interfaces heimdal's krb5 and gssapi libraries use, over wolfSSL's
 * OpenSSL 1.1 compatibility layer, so every algorithm still runs in wolfCrypt.
 *
 * wolfSSL has no providers or library contexts: there is one wolfCrypt, configured when it
 * was built. Contexts and providers are therefore tokens, the property query is ignored, and
 * fetching an algorithm looks it up by name. EVP_MAC offers HMAC alone.
 */
#ifndef OSSL3_WOLFSSL_H
#define OSSL3_WOLFSSL_H

#include <stddef.h>
#include <wolfssl/options.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/hmac.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;
typedef struct ossl_provider_st OSSL_PROVIDER;
typedef struct evp_mac_st EVP_MAC;
typedef struct evp_mac_ctx_st EVP_MAC_CTX;

typedef struct ossl_param_st {
    const char *key;
    unsigned int data_type;
    void *data;
    size_t data_size;
    size_t return_size;
} OSSL_PARAM;

/* OpenSSL 3 makes this EVP_CIPHER_CTX_reset, which returns success; wolfSSL's returns void. */
#undef EVP_CIPHER_CTX_init
#define EVP_CIPHER_CTX_init(ctx) (wolfSSL_EVP_CIPHER_CTX_init(ctx), 1)

#define OSSL_PARAM_INTEGER 1
#define OSSL_PARAM_UTF8_STRING 4

#define OSSL_MAC_PARAM_DIGEST "digest"

OSSL_LIB_CTX *OSSL_LIB_CTX_new(void);
OSSL_LIB_CTX *OSSL_LIB_CTX_get0_global_default(void);
int OSSL_LIB_CTX_load_config(OSSL_LIB_CTX *, const char *);
void OSSL_LIB_CTX_free(OSSL_LIB_CTX *);

OSSL_PROVIDER *OSSL_PROVIDER_load(OSSL_LIB_CTX *, const char *);
int OSSL_PROVIDER_unload(OSSL_PROVIDER *);

EVP_CIPHER *EVP_CIPHER_fetch(OSSL_LIB_CTX *, const char *, const char *);
void EVP_CIPHER_free(EVP_CIPHER *);
EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *, const char *, const char *);
void EVP_MD_free(EVP_MD *);
const char *EVP_MD_get0_name(const EVP_MD *);
int EVP_MD_get_size(const EVP_MD *);

EVP_MAC *EVP_MAC_fetch(OSSL_LIB_CTX *, const char *, const char *);
void EVP_MAC_free(EVP_MAC *);
EVP_MAC_CTX *EVP_MAC_CTX_new(EVP_MAC *);
void EVP_MAC_CTX_free(EVP_MAC_CTX *);
int EVP_MAC_init(EVP_MAC_CTX *, const unsigned char *, size_t, const OSSL_PARAM[]);
int EVP_MAC_update(EVP_MAC_CTX *, const unsigned char *, size_t);
int EVP_MAC_final(EVP_MAC_CTX *, unsigned char *, size_t *, size_t);

OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *, char *, size_t);
OSSL_PARAM OSSL_PARAM_construct_int(const char *, int *);
OSSL_PARAM OSSL_PARAM_construct_end(void);
#define OSSL_PARAM_END { NULL, 0, NULL, 0, 0 }

#ifdef __cplusplus
}
#endif

#endif /* OSSL3_WOLFSSL_H */
