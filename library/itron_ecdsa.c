#include "mbedtls/itron_ecdsa.h"
#include "mbedtls/ecdsa.h"

ecdsa_sign_callback itron_ecdsa_sign_callback_ptr = 0;

int mbedtls_ecdsa_can_do(  mbedtls_ecp_group_id __attribute__ ((unused)) gid )
{
    return gid == MBEDTLS_ECP_DP_SECP256R1 ? 1 : 0;
}

#define ECDSA_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
#define ECDSA_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

extern int ecdsa_sign_restartable( mbedtls_ecp_group *grp,
                mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                int (*f_rng_blind)(void *, unsigned char *, size_t),
                void *p_rng_blind,
                mbedtls_ecdsa_restart_ctx *rs_ctx );

int mbedtls_ecdsa_sign(
    mbedtls_ecp_group *grp,
    mbedtls_mpi *r,
    mbedtls_mpi *s,
    const mbedtls_mpi *d,
    const unsigned char *buf,
    size_t blen,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng )
{
    if (itron_ecdsa_sign_callback_ptr)
    {
        return itron_ecdsa_sign_callback_ptr(grp, r, s, d, buf, blen, f_rng, p_rng);
    }
    else
    {
        ECDSA_VALIDATE_RET( grp   != NULL );
        ECDSA_VALIDATE_RET( r     != NULL );
        ECDSA_VALIDATE_RET( s     != NULL );
        ECDSA_VALIDATE_RET( d     != NULL );
        ECDSA_VALIDATE_RET( f_rng != NULL );
        ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );

        /* Use the same RNG for both blinding and ephemeral key generation */
        return( ecdsa_sign_restartable( grp, r, s, d, buf, blen,
                                        f_rng, p_rng, f_rng, p_rng, NULL ) );
    }
}
