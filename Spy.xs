#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

static SV *
my_fetch_ref(pTHX_ AV *av, IV key, IV mandatory) {
    SV **svp = av_fetch(av, key, 0);
    if (svp) {
        SV *sv = *svp;
        if (sv && SvOK(sv)) {
            if (SvROK(sv)) return sv;
            Perl_croak(aTHX_ "internal error: reference expected on slot %d", key);
        }
    }
    if (mandatory)
        Perl_croak(aTHX_ "internal error: reference expected on slot %d, undef found", key);
    return NULL;
}

#define fetch(av, key) my_fetch_ref(aTHX_ av, key, 0)
#define fetch_hv(av) ((HV*)SvRV((my_fetch_ref(aTHX_ av, 0, 1))))

#define ADD    1
#define CHANGE 2
#define STORE  3
#define CLEAR  4
#define EMPTY  5

void
callback(pTHX_ SV *cb, U32 argc, ...) {
    dSP;
    ENTER;
    PUSHMARK(SP);
    if (argc > 0) {
        va_list args;
        va_start(args, argc);
        EXTEND(SP, argc);
        do {
            SV *const sv = va_arg(args, SV *);
            PUSHs(sv);
        } while (--argc);
        va_end(args);
    }
    PUTBACK;
    call_sv(cb, G_SCALAR|G_DISCARD);
    LEAVE;
}

MODULE = Hash::Spy		PACKAGE = Hash::Spy		

SV *
_hash_get_spy(HV *hv)
PREINIT:
    const MAGIC *mg;
CODE:
    if (mg = SvTIED_mg((SV*)hv, PERL_MAGIC_tied)) {
        RETVAL = SvTIED_obj((SV*)hv, mg);
        if (!sv_isa(RETVAL, "Hash::Spy"))
            perl_croak(aTHX_ "Hash::Spy does not support tied hashes");
    }
    else {
        AV *av = newAV();
        SV *weak = newRV_inc((SV*)hv);
        sv_rvweaken(weak);
        av_store(av, 0, weak);
        RETVAL = newRV_noinc((SV*)av);
        sv_bless(RETVAL, gv_stashpvs("Hash::Spy", 1));
        hv_magic(hv, RETVAL, PERL_MAGIC_tied);
    }
OUTPUT:
    RETVAL

SV *
FETCH(AV *spy, SV *key)
PREINIT:
    HV *hv;
    HE *he;
CODE:
    hv = fetch_hv(spy);
    SvRMAGICAL_off(hv);
    he = hv_fetch_ent(hv, key, 0, 0);
    RETVAL = hv_iterval(hv, he);
    SvRMAGICAL_on(hv);
    SvREFCNT_inc(RETVAL);
OUTPUT:
    RETVAL

void
STORE(AV *spy, SV *key, SV *value)
PREINIT:
    HV *hv;
CODE:
    hv = fetch_hv(spy);
    SvRMAGICAL_off(hv);
    SvREFCNT_inc(value);
    if (!hv_store_ent(hv, key, value, 0)) sv_2mortal(value);
    SvRMAGICAL_on(hv);

SV *
DELETE(AV *spy, SV *key)
PREINIT:
    HV *hv;
CODE:
    hv = fetch_hv(spy);
    SvRMAGICAL_off(hv);
    RETVAL = hv_delete_ent(hv, key, 0, 0);
    SvRMAGICAL_on(hv);
    SvREFCNT_inc(RETVAL);
OUTPUT:
    RETVAL

void
CLEAR(AV *spy)
PREINIT:
    HV *hv;
    SV *cb;
CODE:
    hv = fetch_hv(spy);
    if (cb = fetch(spy, CLEAR)) callback(aTHX_ cb, 0);
    SvRMAGICAL_off(hv);
    hv_clear(hv);
    SvRMAGICAL_on(hv);
    if (cb = fetch(spy, EMPTY)) callback(aTHX_ cb, 0);

SV *
EXISTS(AV *spy, SV *key)
PREINIT:
    HV *hv;
CODE:
    hv = fetch_hv(spy);
    SvRMAGICAL_off(hv);
    RETVAL = (hv_exists_ent(hv, key, 0) ? &PL_sv_yes : &PL_sv_no);
    SvRMAGICAL_on(hv);
OUTPUT:
    RETVAL

SV *
FIRSTKEY(AV *spy)
PREINIT:
    HV *hv;
CODE:
    hv = fetch_hv(spy);
    SvRMAGICAL_off(hv);
    hv_iterinit(hv);
    SvRMAGICAL_on(hv);
    RETVAL = &PL_sv_yes;
OUTPUT:
    RETVAL

SV *
NEXTKEY(AV *spy)
PREINIT:
    HV *hv;
    HE *he;
CODE:
    hv = fetch_hv(spy);
    SvRMAGICAL_off(hv);
    if (he = hv_iternext(hv)) {
        RETVAL = hv_iterkeysv(he);
    }
    else {
        RETVAL = &PL_sv_undef;
    }
    SvRMAGICAL_on(hv);
    SvREFCNT_inc(RETVAL);
OUTPUT:
    RETVAL

SV *
SCALAR(AV *spy)
PREINIT:
    HV *hv;
CODE:
    hv = fetch_hv(spy);
    SvRMAGICAL_off(hv);
    RETVAL = hv_scalar(hv);
    SvRMAGICAL_on(hv);
    SvREFCNT_inc(RETVAL);
OUTPUT:
    RETVAL

void
UNTIE(AV *spy)

