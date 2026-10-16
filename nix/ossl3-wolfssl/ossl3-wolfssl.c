#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "ossl3-wolfssl.h"

struct ossl_lib_ctx_st {
    int unused;
};

struct ossl_provider_st {
    const char *name;
};

struct evp_mac_st {
    int unused;
};

struct evp_mac_ctx_st {
    HMAC_CTX *hmac;
    const EVP_MD *md;
};

static OSSL_LIB_CTX the_lib_ctx;
static OSSL_PROVIDER default_provider = { "default" };
static OSSL_PROVIDER legacy_provider = { "legacy" };
#ifdef HAVE_FIPS
static OSSL_PROVIDER fips_provider = { "fips" };
#endif
static EVP_MAC hmac_mac;

OSSL_LIB_CTX *
OSSL_LIB_CTX_new(void)
{
    return &the_lib_ctx;
}

OSSL_LIB_CTX *
OSSL_LIB_CTX_get0_global_default(void)
{
    return &the_lib_ctx;
}

/* wolfSSL reads no openssl.cnf; its configuration is fixed when it is built. */
int
OSSL_LIB_CTX_load_config(OSSL_LIB_CTX *ctx, const char *path)
{
    (void)ctx;
    (void)path;
    return 1;
}

void
OSSL_LIB_CTX_free(OSSL_LIB_CTX *ctx)
{
    (void)ctx;
}

/*
 * "default" and "legacy" name algorithm sets that wolfSSL either has built in or lacks, so
 * loading them always succeeds; a fetch of a missing algorithm fails instead. "fips"
 * succeeds only against the FIPS module.
 */
OSSL_PROVIDER *
OSSL_PROVIDER_load(OSSL_LIB_CTX *ctx, const char *name)
{
    (void)ctx;
    if (name == NULL)
        return NULL;
    if (strcmp(name, "default") == 0)
        return &default_provider;
    if (strcmp(name, "legacy") == 0)
        return &legacy_provider;
#ifdef HAVE_FIPS
    if (strcmp(name, "fips") == 0)
        return &fips_provider;
#endif
    return NULL;
}

int
OSSL_PROVIDER_unload(OSSL_PROVIDER *provider)
{
    (void)provider;
    return 1;
}

/* wolfSSL's EVP_CIPHER and EVP_MD are the algorithms' static names; there is nothing to free. */
EVP_CIPHER *
EVP_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *name, const char *propq)
{
    (void)ctx;
    (void)propq;
    return (EVP_CIPHER *)EVP_get_cipherbyname(name);
}

void
EVP_CIPHER_free(EVP_CIPHER *cipher)
{
    (void)cipher;
}

EVP_MD *
EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *name, const char *propq)
{
    (void)ctx;
    (void)propq;
    return (EVP_MD *)EVP_get_digestbyname(name);
}

void
EVP_MD_free(EVP_MD *md)
{
    (void)md;
}

const char *
EVP_MD_get0_name(const EVP_MD *md)
{
    return (const char *)md;
}

int
EVP_MD_get_size(const EVP_MD *md)
{
    return EVP_MD_size(md);
}

EVP_MAC *
EVP_MAC_fetch(OSSL_LIB_CTX *ctx, const char *name, const char *propq)
{
    (void)ctx;
    (void)propq;
    if (name == NULL || strcasecmp(name, "HMAC") != 0)
        return NULL;
    return &hmac_mac;
}

void
EVP_MAC_free(EVP_MAC *mac)
{
    (void)mac;
}

EVP_MAC_CTX *
EVP_MAC_CTX_new(EVP_MAC *mac)
{
    EVP_MAC_CTX *ctx;

    if (mac != &hmac_mac)
        return NULL;
    if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
        return NULL;
    if ((ctx->hmac = HMAC_CTX_new()) == NULL) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

void
EVP_MAC_CTX_free(EVP_MAC_CTX *ctx)
{
    if (ctx == NULL)
        return;
    HMAC_CTX_free(ctx->hmac);
    free(ctx);
}

/*
 * The digest parameter picks the hash. A NULL key keeps the previous key, as in OpenSSL;
 * wolfSSL's HMAC_Init_ex reuses it.
 */
int
EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen,
             const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    for (p = params; p != NULL && p->key != NULL; p++) {
        if (strcmp(p->key, OSSL_MAC_PARAM_DIGEST) != 0)
            return 0;
        if (p->data_type != OSSL_PARAM_UTF8_STRING ||
            (ctx->md = EVP_get_digestbyname(p->data)) == NULL)
            return 0;
    }
    if (ctx->md == NULL || keylen > INT_MAX)
        return 0;
    return HMAC_Init_ex(ctx->hmac, key, (int)keylen, ctx->md, NULL) == 1;
}

int
EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t len)
{
    return HMAC_Update(ctx->hmac, data, len) == 1;
}

int
EVP_MAC_final(EVP_MAC_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize)
{
    unsigned int len;

    if (out == NULL) {
        *outl = EVP_MD_size(ctx->md);
        return 1;
    }
    if (outsize < (size_t)EVP_MD_size(ctx->md))
        return 0;
    if (HMAC_Final(ctx->hmac, out, &len) != 1)
        return 0;
    if (outl != NULL)
        *outl = len;
    return 1;
}

OSSL_PARAM
OSSL_PARAM_construct_utf8_string(const char *key, char *buf, size_t bsize)
{
    OSSL_PARAM p = { key, OSSL_PARAM_UTF8_STRING, buf, bsize, 0 };

    if (bsize == 0 && buf != NULL)
        p.data_size = strlen(buf);
    return p;
}

OSSL_PARAM
OSSL_PARAM_construct_int(const char *key, int *buf)
{
    OSSL_PARAM p = { key, OSSL_PARAM_INTEGER, buf, sizeof(int), 0 };

    return p;
}

OSSL_PARAM
OSSL_PARAM_construct_end(void)
{
    OSSL_PARAM p = OSSL_PARAM_END;

    return p;
}
