/*
 * PKCS #11 implementation of Secure Remote Passwords.
 * This code modifies the user side only, replacing password by PKCS #11 key.
 * As a result, token-protected SRP is possible.  This might impose a new
 * consideration on the investigative work on an Elliptic Curve SRP variation.
 * Copyright (c) 2015 Rick van Rein, ARPA2.net.  All rights reserved.
 *
 * Forked from:
 * Secure Remote Password 6a implementation
 * Copyright (c) 2010 Tom Cocagne. All rights reserved.
 * https://github.com/cocagne/csrp
 *
 * The MIT License (MIT)
 * 
 * Copyright (c) 2013 Tom Cocagne
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

/* 
 * 
 * Purpose:       This is a PKCS #11 based implementation of the user side
 *                of Secure Remote Password, version 6a, as described by
 *                http://srp.stanford.edu/design.html
 * 
 * Author:        rick@openfortress.nl (Rick van Rein)
 *                tom.cocagne@gmail.com (Tom Cocagne)
 * 
 * Dependencies:  OpenSSL (and Advapi32.lib on Windows)
 *                PKCS #11 library (any, really)
 * 
 * Usage:         Refer to test_srp11.c for a demonstration
 * 
 * Notes:
 *    This library allows multiple combinations of hashing algorithms and 
 *    prime number constants. For authentication to succeed, the hash and
 *    prime number constants must match between srp11_create_new_keys(),
 *    srp11_create_salted_verification_key(), srp11_user_new(),
 *    and srp_verifier_new(). A recommended approach is to determine the
 *    desired level of security for an application and globally define the
 *    hash and prime number constants to the predetermined values.
 * 
 *    As one might suspect, more bits means more security. As one might also
 *    suspect, more bits also means more processing time. The test_srp11.c 
 *    program can be easily modified to profile various combinations of 
 *    hash & prime number pairings.
 */

#ifndef SRP11_H
#define SRP11_H

#include "srp.h"

struct SRP11User;

#define MAXNUM_EXTRA_ATTRS 20

/* Out: srp11pub, srp11priv
 *
 * The caller is responsible for future lookups of the key, as well as its
 * destruction.  When the attrs is NULL and/or numattrs is 0, then there
 * are no user-defined CKA_xxx fields, and that automatically makes the
 * returned key a session key (CKA_TOKEN defaults to CK_FALSE) and so the
 * cleanup is then automatically done at the end of the PKCS #11 session,
 * if not done by the calling application.
 *
 * The attrs/numattrs define additional PKCS #11 attributes that will be
 * applied to both the public and private key, and can be used to enable
 * future lookups of the keys to be generated.  The following attributes
 * will be provided by the routine, and should not be setup in the
 * attrs/nummattrs: CKA_CLASS, CKA_KEY_TYPE, CKA_PRIME, CKA_BASE,
 * CKA_VALUE, CKA_DERIVE.
 *
 * The generated key pair will be a Diffie-Hellman key pair that can use
 * the CKM_DH_PKCS_DERIVE mechanism for modular exponentiation, which is
 * needed for the further operation of these functions.
 */
CK_RV srp11_create_new_keys ( CK_SESSION_HANDLE p11ses,
		CK_ATTRIBUTE_PTR attrs, CK_ULONG numattrs,
		SRP_NGType ng_type, const char * n_hex, const char * g_hex,
		CK_OBJECT_HANDLE_PTR srp11pub, CK_OBJECT_HANDLE_PTR srp11priv);

/* It is possible in theory to destroy a public key srp11pub as returned
 * from srp11_create_new_keys() and then to use srp11_regenerate_pubkey() to
 * reconstruct it.  This is generally an extra modular exponentiation step,
 * and so not something to take lightly, but it may help to be able to
 * keep PKCS #11 storage space to a bare minimum, and perhaps implement a
 * caching mechanism for public key.  One possibility is to store the public
 * key as a session key, for example.  Use wisely and thou might propsper.
 * Use badly and thou might perish.  When in doubt, don't do this at all.
 *
 * Output: srp11pub
 */
CK_RV srp11_renegerate_pubkey (CK_SESSION_HANDLE p11ses,
				CK_OBJECT_HANDLE srp11priv,
				CK_ATTRIBUTE_PTR attrs, CK_ULONG numattrs,
				CK_OBJECT_HANDLE_PTR srp11pub);

/* The user creation function does not work from a public key handle in PKCS #11
 * but rather from a private key and an already-retrieved public key represented
 * as a byte sequence of the same length and no larger than the private key
 * modulus.  The public key is never used within PKCS #11, so it is possible for
 * the application to retrieve the public key for each session or once and then
 * store the outcome locally, somehow.  In both cases, this function is called
 * to map the PKCS #11 public key object to a byte sequence that can be fed to
 * the srp11_user_new() function.
 */
CK_RV srp11_retrieve_pubkey (CK_SESSION_HANDLE p11ses,
				CK_OBJECT_HANDLE srp11pub,
				unsigned char **bytes_pubkey, int *len_pubkey);

/* Create a new salt/verifier pair for a given service.
 *
 * This is done outside of an SRP protocol session; it generates the information
 * to be able to run an SRP session later on.  Specifically, the verifier is
 * made through PKCS #11 using the SRP #11 modification of SRP 6a.  This means
 * that verification can only be done with srp11_user_process_challenge().
 *
 * SRP #11 only modifies the user side of the SRP protocol, though.  There is no
 * need to inform the service of using PKCS #11.  This means that the standard
 * protocol can be used as is, and that only the user needs to be aware that his
 * token is required to complete authentication.
 *
 * The API used by SRP #11 does not lookup records by username.  Please make
 * sure to add attributes such as CKA_ID and/or CKA_LABEL with sufficient
 * information to reproduce whatever is needed to relocate the keys.  Also,
 * be aware that the default result of this call is a session key pair, not
 * a token-stored key pair.
 *
 * The public key may be treated with some variations.  Please read what was
 * described for srp11_regenerate_pubkey() and srp11_retrieve_pubkey().
 *
 * The caller is responsible for freeing the memory allocated for bytes_s and
 * bytes_v when these are no longer needed.
 * 
 * The n_hex and g_hex parameters should be 0 unless SRP_NG_CUSTOM is used for
 * ng_type.  If provided, they must be numbers in hexidecimal notation.
 *
 * The function may be called with bytes_s en len_s filled in; this can be
 * used to supply more than a hash length of salt info to the function.  If
 * this is done, then the first hash length range of bytes will still be
 * replaced with PKCS #11 generated random bytes, but the rest is kept as-is
 * and will be taken along when computing x'' = H(s)^P * P and v'' = g^x
 * 
 * Outputs: bytes_s, len_s, bytes_v, len_v
 */
CK_RV srp11_create_salted_verification_key(
				CK_SESSION_HANDLE p11ses,
				CK_OBJECT_HANDLE srp11priv,
				unsigned char *bytes_pubkey, int len_pubkey,
				SRP_HashAlgorithm alg,
				unsigned char **bytes_s, int *len_s, 
				unsigned char **bytes_v, int *len_v);


/*******************************************************************************/

/* Fill an administrative structure for the user end of the SRP #11 protocol.
 * The PKCS #11 handles also move into the structure, so they do not need to
 * be repeated.  The modulus and base, together the group parameters, are
 * taken from the public key in srp11pub, where they were left by the
 * srp11_create_new_keys() routine.
 *
 * The caller must supply the same srp11pub, srp11priv and alg parameters
 * as used during srp11_create_new_keys(); the srp11pub and srp11priv may
 * be different handles, for instance when looked up in another session,
 * but they must refer to the same key material.  See also the
 * srp11_regenerate_pubkey() for another degree of freedom; the public key
 * in srp11pub may in fact have been regenerated from srp11priv to find the
 * same key material.
 *
 * After the PKCS #11 session and key material have been supplied, they
 * are considered at least as stable as the resulting user structure;
 * that is, the session should not be closed and the keys not removed if
 * calls on the SRP11User structure other than srp11_user_delete() are to
 * work.
 *
 * Output: user
 */
CK_RV srp11_user_new (
			CK_SESSION_HANDLE p11ses,
			CK_OBJECT_HANDLE srp11priv,
			SRP_HashAlgorithm alg,
			unsigned char *bytes_pubkey, int len_pubkey,
			char *username,
			struct SRP11User **user);


/* End the SRP #11 protocol end for the user.
 *
 * Although the SRP11User structure refers to a PKCS #11 session and
 * key material, these are not closed or otherwise unshared; just like the
 * SRP #11 application opens the session and locates keys to use, it is also
 * responsible for destuction of keys and closing of sessions.
 */
void srp11_user_delete (struct SRP11User *user);


/* Check whether the SRP #11 session is authenticated.  Nonzero confirms.
 */
int srp11_user_is_authenticated (struct SRP11User *user);


/* key_length may be null */
int srp11_user_get_session_key_length (struct SRP11User *user);
unsigned char *srp11_user_get_session_key (struct SRP11User *user,
					int *key_length);


/* First step in the user-side of authentication:
 *  1. Pick a random number a sized like the secure hash
 *  2. Compute A = g^a with the PKCS #11 token
 *  3. Output the value A for transmission to the service
 *
 * Upon failure, partial results may have gotten stored in the user
 * structure.  They only proper course of action is then to cleanup
 * through srp11_delete_user() because calling this procedure again
 * might overwrite those half-done fields, and lead to memory leaks.
 * The *byte_A value will not be allocated in case of failure.
 *
 * Output: bytes_A, len_A
 */
CK_RV srp11_user_start_authentication (
			struct SRP11User *user,
			unsigned char **bytes_A, int *len_A);

/* Second step in user-side authentication: Receive B and s, produce M.
 *
 * This performs computations that are specific for PKCS #11 and that will
 * only validate against the salt and verifier output from
 * srp11_create_salted_verification_key().  Other than this, the server
 * may follow the customary SRP 6a procedure.  In other words, for SRP #11
 * there does not have to be a change to the server or its code, only the
 * generation and challenge processing on the user-side change to accommodate
 * the constraints and extra design requirements of PKCS #11.
 *
 * Upon failure, partial results may have gotten stored in the user
 * structure.  They only proper course of action is then to cleanup
 * through srp11_delete_user() because calling this procedure again
 * might overwrite those half-done fields, and lead to memory leaks.
 * The *byte_M value will not be allocated in case of failure.
 *
 * Outputs: bytes_M/len_M.
 */
CK_RV srp11_user_process_challenge (
			struct SRP11User *user, 
			unsigned char *bytes_s, int len_s, 
			unsigned char *bytes_B, int len_B,
			unsigned char **bytes_M, int *len_M);

/* bytes_HAMK must be exactly srp11_user_get_session_key_length() bytes in size */
CK_RV srp11_user_verify_session (struct SRP11User *user,
				unsigned char *bytes_HAMK);

#endif /* Include Guard */
