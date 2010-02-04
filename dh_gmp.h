/* $Id$
 *
 * Copyright (c) 2008 Daisuke Maki <daisuke@endeworks.jp>
 */

#ifndef __DH_GMP_H__
#define __DH_GMP_H__

#include <gmp.h>
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

typedef char *  DH_gmp_value;
typedef mpz_t   DH_mpz_t;

typedef struct {
    mpz_t *p;
    mpz_t *g;
    mpz_t *priv_key;
    mpz_t *pub_key;
} DH_gmp_t;

#endif /* __DH_GMP_H__ */

