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

#define SAVED_ITER 1

#define DELETE 2
#define STORE  3
#define CLEAR  4
#define EMPTY  5

static void
spyback(pTHX_ AV *spy, HV *hv, int slot, U32 argc, ...) {
    SV *cb = fetch(spy, slot);
    if (cb) {
        dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        EXTEND(SP, argc + 1);
        PUSHs(sv_2mortal(newRV_inc((SV*)hv)));
        if (argc > 0) {
            va_list args;
            va_start(args, argc);
            do {
                SV *const sv = va_arg(args, SV *);
                PUSHs(sv_mortalcopy(sv));
            } while (--argc);
            va_end(args);
        }
        PUTBACK;
        call_sv(cb, G_SCALAR|G_DISCARD);
        FREETMPS;
        LEAVE;
    }
}

static void
switch_hv_aux(pTHX_ AV *spy, HV *hv) {
    if (SvOOK((SV*)hv)) {
        SV **svp = av_fetch(spy, SAVED_ITER, 0);
        if (svp) {
            SV *sv = *svp;
            if (sv && SvPOK(sv) && (SvCUR(sv) == sizeof(struct xpvhv_aux))) {
                char tmp[sizeof(struct xpvhv_aux)];
                char *pv = SvPVX(sv);
                Copy(pv,        tmp,       sizeof(struct xpvhv_aux), char);
                Copy(HvAUX(hv), pv,        sizeof(struct xpvhv_aux), char);
                Copy(tmp,       HvAUX(hv), sizeof(struct xpvhv_aux), char);
                return;
            }
        }
        Perl_croak(aTHX_ "internal error: saved HV iter missing");
    }
    Perl_croak(aTHX_ "internal error: HV OOK flag is unset");
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
        SV *store;
        struct xpvhv_aux* iter;
        sv_rvweaken(weak);
        av_store(av, 0, weak);
        RETVAL = newRV_noinc((SV*)av);
        sv_bless(RETVAL, gv_stashpvs("Hash::Spy", 1));
        if (!SvOOK(hv)) {
            hv_iterinit(hv);
            if (!SvOOK(hv))
                Perl_croak(aTHX_ "internal error: hv_iterinit did not set OOK");
        }
        iter = HvAUX(hv);
        av_store(av, SAVED_ITER, newSVpvn((char *)iter, sizeof(*iter)));
        HvEITER_set(hv, 0);
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
    spyback(aTHX_ spy, hv, STORE, 2, key, value);
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
    spyback(aTHX_ spy, hv, DELETE, 1, key);
    SvRMAGICAL_off(hv);
    switch_hv_aux(aTHX_ spy, hv);
    RETVAL = hv_delete_ent(hv, key, 0, 0);
    switch_hv_aux(aTHX_ spy, hv);
    SvRMAGICAL_on(hv);
    SvREFCNT_inc(RETVAL);
    if (!HvTOTALKEYS(hv))
        spyback(aTHX_ spy, hv, EMPTY, 0);
OUTPUT:
    RETVAL

void
CLEAR(AV *spy)
PREINIT:
    HV *hv;
    SV *cb;
CODE:
    hv = fetch_hv(spy);
    spyback(aTHX_ spy, hv, CLEAR, 0);
    SvRMAGICAL_off(hv);
    switch_hv_aux(aTHX_ spy, hv);
    hv_clear(hv);
    switch_hv_aux(aTHX_ spy, hv);
    SvRMAGICAL_on(hv);
    if (!HvTOTALKEYS(hv))
        spyback(aTHX_ spy, hv, EMPTY, 0);

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
    HE *he;
CODE:
    hv = fetch_hv(spy);
    SvRMAGICAL_off(hv);
    switch_hv_aux(aTHX_ spy, hv);
    hv_iterinit(hv);
    if (he = hv_iternext(hv)) {
        RETVAL = hv_iterkeysv(he);
    }
    else {
        RETVAL = &PL_sv_undef;
    }
    switch_hv_aux(aTHX_ spy, hv);
    SvRMAGICAL_on(hv);
    SvREFCNT_inc(RETVAL);
OUTPUT:
    RETVAL

SV *
NEXTKEY(AV *spy, SV *last)
PREINIT:
    HV *hv;
    HE *he;
CODE:
    hv = fetch_hv(spy);
    SvRMAGICAL_off(hv);
    switch_hv_aux(aTHX_ spy, hv);
    if (he = hv_iternext(hv)) {
        RETVAL = hv_iterkeysv(he);
    }
    else {
        RETVAL = &PL_sv_undef;
    }
    switch_hv_aux(aTHX_ spy, hv);
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
CODE:
    av_clear(spy);

