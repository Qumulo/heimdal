/*
 * Computes Kerberos MIC checksums from several threads on one krb5_crypto, the way gsskrb5's
 * gss_get_mic and gss_verify_mic (and their iov forms) use a context's crypto when callers
 * share a context between threads. Each result is compared with one computed alone.
 *
 * Usage: mic-threads ENCTYPE THREADS ITERATIONS ROUNDS [warm|separate]
 * Each round makes a fresh krb5_crypto, so first use of each key usage also races, unless "warm"
 * computes one checksum per usage before the threads start. "separate" gives each thread its own
 * krb5_crypto instead, the way qfsd uses Heimdal: contexts run in parallel, each on one thread.
 * Exits 1 if any thread saw a wrong checksum or an error.
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <krb5.h>

#define MESSAGES 64
#define MAX_MESSAGE 4096
#define MAX_CHECKSUM 64

static const unsigned usages[] = { KRB5_KU_USAGE_ACCEPTOR_SIGN, KRB5_KU_USAGE_INITIATOR_SIGN };
#define USAGES (sizeof(usages) / sizeof(usages[0]))

static unsigned char messages[MESSAGES][MAX_MESSAGE];
static size_t message_lengths[MESSAGES];
static unsigned char expected[USAGES][MESSAGES][MAX_CHECKSUM];
static size_t checksum_length;

static krb5_keyblock key;
static krb5_crypto shared_crypto;
static int iterations, separate;
static atomic_int wrong, errors;
static pthread_barrier_t start;

static krb5_error_code
checksum(krb5_context context, krb5_crypto crypto, unsigned usage, int m, unsigned char *out)
{
    krb5_crypto_iov iov[2];

    iov[0].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[0].data.data = messages[m];
    iov[0].data.length = message_lengths[m];
    iov[1].flags = KRB5_CRYPTO_TYPE_CHECKSUM;
    iov[1].data.data = out;
    iov[1].data.length = checksum_length;
    return krb5_create_checksum_iov(context, crypto, usage, iov, 2, NULL);
}

static void *
worker(void *arg)
{
    long id = (long)arg;
    krb5_context context;
    krb5_crypto crypto = shared_crypto;
    unsigned char out[MAX_CHECKSUM];

    if (krb5_init_context(&context) != 0)
        abort();
    if (separate && krb5_crypto_init(context, &key, 0, &crypto) != 0)
        abort();
    pthread_barrier_wait(&start);
    for (int i = 0; i < iterations; i++) {
        size_t u = (id + i) % USAGES;
        int m = (id * 7 + i) % MESSAGES;

        if (checksum(context, crypto, usages[u], m, out) != 0)
            atomic_fetch_add(&errors, 1);
        else if (memcmp(out, expected[u][m], checksum_length) != 0)
            atomic_fetch_add(&wrong, 1);
    }
    if (separate)
        krb5_crypto_destroy(context, crypto);
    krb5_free_context(context);
    return NULL;
}

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_enctype enctype;
    krb5_crypto crypto;
    int threads, rounds, warm;

    if (argc != 5 && argc != 6) {
        fprintf(stderr, "usage: %s ENCTYPE THREADS ITERATIONS ROUNDS [warm|separate]\n", argv[0]);
        return 2;
    }
    threads = atoi(argv[2]);
    iterations = atoi(argv[3]);
    rounds = atoi(argv[4]);
    warm = argc == 6 && strcmp(argv[5], "warm") == 0;
    separate = argc == 6 && strcmp(argv[5], "separate") == 0;

    if (krb5_init_context(&context) != 0 ||
        krb5_string_to_enctype(context, argv[1], &enctype) != 0 ||
        krb5_generate_random_keyblock(context, enctype, &key) != 0 ||
        krb5_crypto_init(context, &key, 0, &crypto) != 0 ||
        krb5_crypto_length(context, crypto, KRB5_CRYPTO_TYPE_CHECKSUM, &checksum_length) != 0 ||
        checksum_length > MAX_CHECKSUM) {
        fprintf(stderr, "setup failed\n");
        return 2;
    }

    for (int m = 0; m < MESSAGES; m++) {
        message_lengths[m] = 1 + (m * 997) % MAX_MESSAGE;
        for (size_t b = 0; b < message_lengths[m]; b++)
            messages[m][b] = (unsigned char)(m * 31 + b);
    }
    for (size_t u = 0; u < USAGES; u++)
        for (int m = 0; m < MESSAGES; m++)
            if (checksum(context, crypto, usages[u], m, expected[u][m]) != 0) {
                fprintf(stderr, "reference checksum failed\n");
                return 2;
            }
    krb5_crypto_destroy(context, crypto);

    for (int r = 0; r < rounds; r++) {
        pthread_t tids[threads];

        if (krb5_crypto_init(context, &key, 0, &shared_crypto) != 0)
            abort();
        for (size_t u = 0; warm && u < USAGES; u++) {
            unsigned char out[MAX_CHECKSUM];

            if (checksum(context, shared_crypto, usages[u], 0, out) != 0)
                abort();
        }
        pthread_barrier_init(&start, NULL, threads);
        for (long t = 0; t < threads; t++)
            pthread_create(&tids[t], NULL, worker, (void *)t);
        for (int t = 0; t < threads; t++)
            pthread_join(tids[t], NULL);
        pthread_barrier_destroy(&start);
        krb5_crypto_destroy(context, shared_crypto);
    }

    printf("%s%s%s: %d threads x %d iterations x %d rounds: %d wrong, %d errors\n", argv[1],
           warm ? " (warm)" : "", separate ? " (separate)" : "", threads, iterations, rounds, atomic_load(&wrong),
           atomic_load(&errors));
    krb5_free_keyblock_contents(context, &key);
    krb5_free_context(context);
    return (wrong || errors) ? 1 : 0;
}
