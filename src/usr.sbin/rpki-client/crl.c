/*	$OpenBSD: crl.c,v 1.37 2024/06/05 13:36:28 tb Exp $ */
/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/x509.h>

#include "extern.h"

/*
 * Check that the CRL number extension is present and that it is non-critical.
 * Otherwise ignore it per draft-spaghetti-sidrops-rpki-crl-numbers.
 */
static int
crl_has_crl_number(const char *fn, const X509_CRL *x509_crl)
{
	const X509_EXTENSION	*ext;
	int			 idx;

	if ((idx = X509_CRL_get_ext_by_NID(x509_crl, NID_crl_number, -1)) < 0) {
		warnx("%s: RFC 6487, section 5: missing CRL number", fn);
		return 0;
	}
	if ((ext = X509_CRL_get_ext(x509_crl, idx)) == NULL) {
		warnx("%s: RFC 6487, section 5: failed to get CRL number", fn);
		return 0;
	}
	if (X509_EXTENSION_get_critical(ext) != 0) {
		warnx("%s: RFC 6487, section 5: CRL number not non-critical",
		    fn);
		return 0;
	}

	return 1;
}

/*
 * Parse X509v3 authority key identifier (AKI) from the CRL.
 * Returns the AKI or NULL if it could not be parsed.
 * The AKI is formatted as a hex string.
 */
static char *
crl_get_aki(const char *fn, X509_CRL *x509_crl)
{
	AUTHORITY_KEYID		*akid = NULL;
	ASN1_OCTET_STRING	*os;
	const unsigned char	*d;
	int			 dsz, crit;
	char			*res = NULL;

	if ((akid = X509_CRL_get_ext_d2i(x509_crl, NID_authority_key_identifier,
	    &crit, NULL)) == NULL) {
		if (crit != -1)
			warnx("%s: RFC 6487 section 4.8.3: AKI: "
			    "failed to parse CRL extension", fn);
		else
			warnx("%s: RFC 6487 section 4.8.3: AKI: "
			    "CRL extension missing", fn);
		goto out;
	}
	if (crit != 0) {
		warnx("%s: RFC 6487 section 4.8.3: "
		    "AKI: extension not non-critical", fn);
		goto out;
	}
	if (akid->issuer != NULL || akid->serial != NULL) {
		warnx("%s: RFC 6487 section 4.8.3: AKI: "
		    "authorityCertIssuer or authorityCertSerialNumber present",
		    fn);
		goto out;
	}

	os = akid->keyid;
	if (os == NULL) {
		warnx("%s: RFC 6487 section 4.8.3: AKI: "
		    "Key Identifier missing", fn);
		goto out;
	}

	d = os->data;
	dsz = os->length;

	if (dsz != SHA_DIGEST_LENGTH) {
		warnx("%s: RFC 6487 section 4.8.3: AKI: "
		    "want %d bytes SHA1 hash, have %d bytes",
		    fn, SHA_DIGEST_LENGTH, dsz);
		goto out;
	}

	res = hex_encode(d, dsz);
 out:
	AUTHORITY_KEYID_free(akid);
	return res;
}

/*
 * Check that the list of revoked certificates contains only the specified
 * two fields, Serial Number and Revocation Date, and that no extensions are
 * present.
 */
static int
crl_check_revoked(const char *fn, X509_CRL *x509_crl)
{
	STACK_OF(X509_REVOKED)	*list;
	X509_REVOKED		*revoked;
	int			 count, i;

	/* If there are no revoked certificates, there's nothing to check. */
	if ((list = X509_CRL_get_REVOKED(x509_crl)) == NULL)
		return 1;

	if ((count = sk_X509_REVOKED_num(list)) <= 0) {
		/*
		 * XXX - as of May 2024, ~15% of RPKI CRLs fail this check due
		 * to a bug in rpki-rs/Krill. So silently accept this for now.
		 * https://github.com/NLnetLabs/krill/issues/1197
		 */
		if (verbose > 1)
			warnx("%s: RFC 5280, section 5.1.2.6: revoked "
			    "certificate list without entries disallowed", fn);
		return 1;
	}

	for (i = 0; i < count; i++) {
		revoked = sk_X509_REVOKED_value(list, i);

		/*
		 * serialNumber and revocationDate are mandatory in the ASN.1
		 * template, so no need to check their presence.
		 *
		 * XXX - due to an old bug in Krill, we can't enforce that
		 * revocationDate is in the past until at least mid-2025:
		 * https://github.com/NLnetLabs/krill/issues/788.
		 */

		if (X509_REVOKED_get0_extensions(revoked) != NULL) {
			warnx("%s: RFC 6487, section 5: CRL entry extensions "
			    "disallowed", fn);
			return 0;
		}
	}

	return 1;
}

struct crl *
crl_parse(const char *fn, const unsigned char *der, size_t len)
{
	const unsigned char	*oder;
	struct crl		*crl;
	const X509_ALGOR	*palg;
	const X509_NAME		*name;
	const ASN1_OBJECT	*cobj;
	const ASN1_TIME		*at;
	int			 count, nid, rc = 0;

	/* just fail for empty buffers, the warning was printed elsewhere */
	if (der == NULL)
		return NULL;

	if ((crl = calloc(1, sizeof(*crl))) == NULL)
		err(1, NULL);

	oder = der;
	if ((crl->x509_crl = d2i_X509_CRL(NULL, &der, len)) == NULL) {
		warnx("%s: d2i_X509_CRL", fn);
		goto out;
	}
	if (der != oder + len) {
		warnx("%s: %td bytes trailing garbage", fn, oder + len - der);
		goto out;
	}

	if (X509_CRL_get_version(crl->x509_crl) != 1) {
		warnx("%s: RFC 6487 section 5: version 2 expected", fn);
		goto out;
	}

	if ((name = X509_CRL_get_issuer(crl->x509_crl)) == NULL) {
		warnx("%s: X509_CRL_get_issuer", fn);
		goto out;
	}
	if (!x509_valid_name(fn, "issuer", name))
		goto out;

	X509_CRL_get0_signature(crl->x509_crl, NULL, &palg);
	if (palg == NULL) {
		warnx("%s: X509_CRL_get0_signature", fn);
		goto out;
	}
	X509_ALGOR_get0(&cobj, NULL, NULL, palg);
	nid = OBJ_obj2nid(cobj);
	if (experimental && nid == NID_ecdsa_with_SHA256) {
		if (verbose)
			warnx("%s: P-256 support is experimental", fn);
	} else if (nid != NID_sha256WithRSAEncryption) {
		warnx("%s: RFC 7935: wrong signature algorithm %s, want %s",
		    fn, nid2str(nid), LN_sha256WithRSAEncryption);
		goto out;
	}

	/*
	 * RFC 6487, section 5: AKI and crlNumber MUST be present, no other
	 * CRL extensions are allowed.
	 */
	if ((count = X509_CRL_get_ext_count(crl->x509_crl)) != 2) {
		warnx("%s: RFC 6487 section 5: unexpected number of extensions "
		    "%d != 2", fn, count);
		goto out;
	}
	if (!crl_has_crl_number(fn, crl->x509_crl))
		goto out;
	if ((crl->aki = crl_get_aki(fn, crl->x509_crl)) == NULL)
		goto out;

	at = X509_CRL_get0_lastUpdate(crl->x509_crl);
	if (at == NULL) {
		warnx("%s: X509_CRL_get0_lastUpdate failed", fn);
		goto out;
	}
	if (!x509_get_time(at, &crl->thisupdate)) {
		warnx("%s: ASN1_TIME_to_tm failed", fn);
		goto out;
	}

	at = X509_CRL_get0_nextUpdate(crl->x509_crl);
	if (at == NULL) {
		warnx("%s: X509_CRL_get0_nextUpdate failed", fn);
		goto out;
	}
	if (!x509_get_time(at, &crl->nextupdate)) {
		warnx("%s: ASN1_TIME_to_tm failed", fn);
		goto out;
	}

	if (!crl_check_revoked(fn, crl->x509_crl))
		goto out;

	rc = 1;
 out:
	if (rc == 0) {
		crl_free(crl);
		crl = NULL;
	}
	return crl;
}

static inline int
crlcmp(struct crl *a, struct crl *b)
{
	int	 cmp;

	cmp = strcmp(a->aki, b->aki);
	if (cmp > 0)
		return 1;
	if (cmp < 0)
		return -1;

	/*
	 * In filemode the mftpath cannot be determined easily,
	 * but it is always set in normal top-down validation.
	 */
	if (a->mftpath == NULL || b->mftpath == NULL)
		return 0;

	cmp = strcmp(a->mftpath, b->mftpath);
	if (cmp > 0)
		return 1;
	if (cmp < 0)
		return -1;

	return 0;
}

RB_GENERATE_STATIC(crl_tree, crl, entry, crlcmp);

/*
 * Find a CRL based on the auth SKI value.
 */
struct crl *
crl_get(struct crl_tree *crlt, const struct auth *a)
{
	struct crl	find;

	if (a == NULL)
		return NULL;

	find.aki = a->cert->ski;
	find.mftpath = a->cert->mft;

	return RB_FIND(crl_tree, crlt, &find);
}

int
crl_insert(struct crl_tree *crlt, struct crl *crl)
{
	return RB_INSERT(crl_tree, crlt, crl) == NULL;
}

void
crl_free(struct crl *crl)
{
	if (crl == NULL)
		return;
	free(crl->aki);
	free(crl->mftpath);
	X509_CRL_free(crl->x509_crl);
	free(crl);
}

void
crl_tree_free(struct crl_tree *crlt)
{
	struct crl	*crl, *tcrl;

	RB_FOREACH_SAFE(crl, crl_tree, crlt, tcrl) {
		RB_REMOVE(crl_tree, crlt, crl);
		crl_free(crl);
	}
}
