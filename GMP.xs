/* $Id$
 *
 * Copyright (c) 2008 Daisuke Maki <daisuke@endeworks.jp>
 */

#ifndef __CRYPT_DH_GMP_XS__
#define __CRYPT_DH_GMP_XS__

#include "dh_gmp.h"

#define DH_G(x)       *((x)->g)
#define DH_P(x)       *((x)->p)
#define DH_PRIVKEY(x) *((x)->priv_key)
#define DH_PUBKEY(x)  *((x)->pub_key)

#define DH_G_PTR(x)       (x)->g
#define DH_P_PTR(x)       (x)->p
#define DH_PRIVKEY_PTR(x) (x)->priv_key
#define DH_PUBKEY_PTR(x)  (x)->pub_key

static
void DH_mpz_rand_set(mpz_t *v, unsigned int bits)
{
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long) time(NULL));
    mpz_urandomb(*v, state, bits);
    gmp_randclear(state);
}

static 
char *DH_mpz2sv_str(mpz_t *v, unsigned int base, unsigned int *length)
{
    STRLEN len = 0;
    char *buf, *buf_end;

    /* len is always >= 1, and might be off (greater) by one than real len */
    len = mpz_sizeinbase(*v, base);
    Newxz(buf, len + 2, char);
    buf_end = buf + len - 1; /* end of storage (-1) */
    mpz_get_str(buf, base, *v);
    if (*buf_end == 0) {
        Renew(buf, len - 1, char); /* got one shorter than expected */
    }

    if (length != NULL)
        *length = len;

    return buf;
}

static 
char *DH_mpz2sv_str_twoc(mpz_t *v)
{
    char *buf;
    unsigned int len = 0;
    unsigned int pad = 0;

    buf = DH_mpz2sv_str(v, 2, &len);
    pad = (8 - len % 8);
    if (pad <= 0 && *buf == '1') {
        pad = 8;
    }

    if (pad > 0) {
        unsigned int ipad = 0;
        char *tmp;
        Newxz(tmp, len + pad + 1, char);
        for (ipad = 0; ipad < pad; ipad++)
            *(tmp + ipad) = '0';
        Copy(buf, tmp + pad, len + 1, char);
        Safefree(buf);
        return tmp;
    }

    return buf;
}

#endif /* __CRYPT_DH_GMP_XS__ */

MODULE = Crypt::DH::GMP       PACKAGE = Crypt::DH::GMP  PREFIX = DH_gmp_ 

PROTOTYPES: DISABLE 

DH_gmp_t *
DH_gmp__xs_new(class, p, g, priv_key = NULL)
        char *class;
        char *p;
        char *g;
        char *priv_key;
    PREINIT:
        DH_gmp_t *dh;
    CODE:
        Newxz(dh, 1, DH_gmp_t);
        Newxz(DH_P_PTR(dh),       1, mpz_t);
        Newxz(DH_G_PTR(dh),       1, mpz_t);
        Newxz(DH_PRIVKEY_PTR(dh), 1, mpz_t);
        Newxz(DH_PUBKEY_PTR(dh),  1, mpz_t);

        mpz_init(DH_PUBKEY(dh));
        mpz_init_set_str(DH_P(dh), p, 0);
        mpz_init_set_str(DH_G(dh), g, 0);
        if (priv_key != NULL && sv_len(ST(3)) > 0) {
            mpz_init_set_str(DH_PRIVKEY(dh), priv_key, 10);
        } else {
            mpz_init_set_ui(DH_PRIVKEY(dh), 0);
        } 

        RETVAL = dh;
    OUTPUT:
        RETVAL

void
DH_gmp_generate_keys(dh)
        DH_gmp_t *dh;
    CODE:
        if (mpz_cmp_ui(DH_PRIVKEY(dh), 0) == 0) {
            mpz_t max;

            /* not initialized, eh? */
            mpz_init(max);
            mpz_sub_ui(max, DH_P(dh), 1);
            do {
                DH_mpz_rand_set(DH_PRIVKEY_PTR(dh), mpz_sizeinbase(DH_P(dh), 2));
            } while ( mpz_cmp(DH_PRIVKEY(dh), max) > 0 );
        }
            
        mpz_powm( DH_PUBKEY(dh), DH_G(dh), DH_PRIVKEY(dh), DH_P(dh) );

char *
DH_gmp_compute_key(dh, pub_key)
        DH_gmp_t *dh;
        char * pub_key;
    PREINIT:
        DH_mpz_t mpz_ret;
        DH_mpz_t mpz_pub_key;
    CODE:
        mpz_init(mpz_ret);
        mpz_init_set_str(mpz_pub_key, pub_key, 0);
        mpz_powm(mpz_ret, mpz_pub_key, DH_PRIVKEY(dh), DH_P(dh));
        RETVAL = DH_mpz2sv_str(&mpz_ret, 10, NULL);
        mpz_clear(mpz_ret);
        mpz_clear(mpz_pub_key);
    OUTPUT:
        RETVAL

char *
DH_gmp_compute_key_twoc(dh, pub_key)
        DH_gmp_t *dh;
        char * pub_key;
    PREINIT:
        DH_mpz_t mpz_ret;
        DH_mpz_t mpz_pub_key;
    CODE:
        mpz_init(mpz_ret);
        mpz_init_set_str(mpz_pub_key, pub_key, 0);
        mpz_powm(mpz_ret, mpz_pub_key, DH_PRIVKEY(dh), DH_P(dh));
        RETVAL = DH_mpz2sv_str_twoc(&mpz_ret);
        mpz_clear(mpz_ret);
        mpz_clear(mpz_pub_key);
    OUTPUT:
        RETVAL

char *
DH_gmp_priv_key(dh)
        DH_gmp_t *dh;
    CODE:
        RETVAL = DH_mpz2sv_str(DH_PRIVKEY_PTR(dh), 10, NULL);
    OUTPUT:
        RETVAL

char *
DH_gmp_pub_key(dh)
        DH_gmp_t *dh;
    CODE:
        RETVAL = DH_mpz2sv_str(DH_PUBKEY_PTR(dh), 10, NULL);
    OUTPUT:
        RETVAL

char *
DH_gmp_pub_key_twoc(dh)
        DH_gmp_t *dh;
    CODE:
        RETVAL = DH_mpz2sv_str_twoc(DH_PUBKEY_PTR(dh));
    OUTPUT:
        RETVAL

char *
DH_gmp_g(dh, ...)
        DH_gmp_t *dh;
    PREINIT:
        STRLEN n_a;
    CODE:
        RETVAL = DH_mpz2sv_str(DH_G_PTR(dh), 10, NULL);
        if (items > 1) {
            mpz_init_set_str( DH_G(dh), (char *) SvPV(ST(1), n_a), 0 );
        }
    OUTPUT:
        RETVAL

char *
DH_gmp_p(dh, ...)
        DH_gmp_t *dh;
    PREINIT:
        STRLEN n_a;
    CODE:
        RETVAL = DH_mpz2sv_str(DH_P_PTR(dh), 10, NULL);
        if (items > 1) {
            mpz_init_set_str( DH_P(dh), (char *) SvPV(ST(1), n_a), 0 );
        }
    OUTPUT:
        RETVAL

void
DESTROY(dh)
        DH_gmp_t *dh;
    CODE:
#ifdef VERY_VERBOSE
        PerlIO_printf(PerlIO_stderr(), "DH->DESTROY called\n" );
#endif
        mpz_clear(DH_P(dh));
        mpz_clear(DH_G(dh));
        mpz_clear(DH_PUBKEY(dh));
        mpz_clear(DH_PRIVKEY(dh));
#ifdef VERY_VERBOSE
        PerlIO_printf(PerlIO_stderr(), "cleared mpz_t\n" );
#endif
        Safefree(DH_P_PTR(dh));
        Safefree(DH_G_PTR(dh));
        Safefree(DH_PRIVKEY_PTR(dh));
        Safefree(DH_PUBKEY_PTR(dh));
#ifdef VERY_VERBOSE
        PerlIO_printf(PerlIO_stderr(), "freed mpz_t\n" );
#endif
        Safefree(dh);
#ifdef VERY_VERBOSE
        PerlIO_printf(PerlIO_stderr(), "DH->DESTROY done\n" );
#endif
        
