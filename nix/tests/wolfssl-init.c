/*
 * Preloaded into heimdal's unit tests. A FIPS wolfSSL has no RNG seed source until
 * wolfSSL_Init installs one, which the application, not heimdal, is responsible for.
 */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

__attribute__((constructor)) static void
init_wolfssl(void)
{
    if (wolfSSL_Init() != WOLFSSL_SUCCESS)
        __builtin_trap();
}
