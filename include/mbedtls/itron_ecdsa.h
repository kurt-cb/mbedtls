#pragma once

#include "mbedtls/ecdsa.h"

typedef int (*ecdsa_sign_callback)( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

extern ecdsa_sign_callback itron_ecdsa_sign_callback_ptr;
