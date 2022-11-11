#include "mbedtls/itron_ecdsa.h"

ecdsa_sign_callback itron_ecdsa_sign_callback_ptr = 0;

int mbedtls_ecdsa_can_do(  mbedtls_ecp_group_id __attribute__ ((unused)) gid )
{
    return gid == MBEDTLS_ECP_DP_SECP256R1 ? 1 : 0;
}

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
        return -1;
    }
}
