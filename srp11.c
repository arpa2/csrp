/*
 * PKCS #11 implementation of Secure Remote Passwords.
 *
 * This code modifies the user side only, replacing password by PKCS #11 key.
 * As a result, token-protected SRP is possible.  This might impose a new
 * consideration on the investigative work on an Elliptic Curve SRP variation.
 *
 * https://github.com/arpa2/srp-pkcs11
 *
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

#ifdef WIN32
    #include <Wincrypt.h>
#else
    #include <sys/time.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <pkcs11.h>

#include "srp.h"
#include "srp11.h"

static int g_initialized = 0;

typedef struct
{
    BIGNUM     * N;
    BIGNUM     * g;
} NGConstant;

struct NGHex 
{
    const char * n_hex;
    const char * g_hex;
};

/* All constants here were pulled from Appendix A of RFC 5054 */
static struct NGHex global_Ng_constants[] = {
 { /* 1024 */
   "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496"
   "EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8E"
   "F4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA"
   "9AFD5138FE8376435B9FC61D2FC0EB06E3",
   "02"
 },
 { /* 1536 */
    "9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA961"
    "4B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F843"
    "80B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0B"
    "E3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF5"
    "6EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734A"
    "F7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E"
    "8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB",
    "02"
 },
 { /* 2048 */
   "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
   "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
   "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
   "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
   "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
   "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
   "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
   "02"
 },
 { /* 4096 */
   "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
   "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
   "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
   "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
   "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
   "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
   "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
   "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
   "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
   "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
   "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
   "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
   "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
   "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
   "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
   "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
   "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
   "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
   "FFFFFFFFFFFFFFFF",
   "05"
 },
 { /* 8192 */
   "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
   "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
   "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
   "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
   "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
   "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
   "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
   "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
   "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
   "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
   "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
   "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
   "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
   "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
   "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
   "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
   "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
   "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
   "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406"
   "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918"
   "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151"
   "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03"
   "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F"
   "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
   "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B"
   "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632"
   "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E"
   "6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA"
   "3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C"
   "5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
   "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC886"
   "2F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6"
   "6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC5"
   "0846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268"
   "359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6"
   "FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
   "60C980DD98EDD3DFFFFFFFFFFFFFFFFF",
   "13"
 },
 {0,0} /* null sentinel */
};


typedef union 
{
    SHA_CTX    sha;
    SHA256_CTX sha256;
    SHA512_CTX sha512;
} HashCTX;



struct SRP11User {
	//
	// Setup in srp11_user_new()
	SRP_HashAlgorithm  hash_alg;
	CK_SESSION_HANDLE p11ses;
	CK_OBJECT_HANDLE srp11priv;
	BIGNUM *pubkey;
	BIGNUM *modulus;
	BIGNUM *base;
	//
	// Setup in srp11_user_start_authentication()
	BIGNUM *a;
	BIGNUM *A;
	// Setup in srp11_user_process_challenge()
	unsigned char H_AMK [SHA512_DIGEST_LENGTH];
	unsigned char session_key [SHA512_DIGEST_LENGTH];
	//
	// Possibly set in srp11_user_verify_service()
	int authenticated;
};


static int hash_init ( SRP_HashAlgorithm alg, HashCTX *c )
{
    switch (alg)
    {
      case SRP_SHA1  : return SHA1_Init( &c->sha );
      case SRP_SHA224: return SHA224_Init( &c->sha256 );
      case SRP_SHA256: return SHA256_Init( &c->sha256 );
      case SRP_SHA384: return SHA384_Init( &c->sha512 );
      case SRP_SHA512: return SHA512_Init( &c->sha512 );
      default:
        return -1;
    };
}

static int hash_update( SRP_HashAlgorithm alg, HashCTX *c, const void *data, size_t len )
{
    switch (alg)
    {
      case SRP_SHA1  : return SHA1_Update( &c->sha, data, len );
      case SRP_SHA224: return SHA224_Update( &c->sha256, data, len );
      case SRP_SHA256: return SHA256_Update( &c->sha256, data, len );
      case SRP_SHA384: return SHA384_Update( &c->sha512, data, len );
      case SRP_SHA512: return SHA512_Update( &c->sha512, data, len );
      default:
        return -1;
    };
}

static int hash_final( SRP_HashAlgorithm alg, HashCTX *c, unsigned char *md )
{
    switch (alg)
    {
      case SRP_SHA1  : return SHA1_Final( md, &c->sha );
      case SRP_SHA224: return SHA224_Final( md, &c->sha256 );
      case SRP_SHA256: return SHA256_Final( md, &c->sha256 );
      case SRP_SHA384: return SHA384_Final( md, &c->sha512 );
      case SRP_SHA512: return SHA512_Final( md, &c->sha512 );
      default:
        return -1;
    };
}
static unsigned char * hash( SRP_HashAlgorithm alg, const unsigned char *d, size_t n, unsigned char *md )
{
    switch (alg)
    {
      case SRP_SHA1  : return SHA1( d, n, md );
      case SRP_SHA224: return SHA224( d, n, md );
      case SRP_SHA256: return SHA256( d, n, md );
      case SRP_SHA384: return SHA384( d, n, md );
      case SRP_SHA512: return SHA512( d, n, md );
      default:
        return 0;
    };
}
static int hash_length( SRP_HashAlgorithm alg )
{
    switch (alg)
    {
      case SRP_SHA1  : return SHA_DIGEST_LENGTH;
      case SRP_SHA224: return SHA224_DIGEST_LENGTH;
      case SRP_SHA256: return SHA256_DIGEST_LENGTH;
      case SRP_SHA384: return SHA384_DIGEST_LENGTH;
      case SRP_SHA512: return SHA512_DIGEST_LENGTH;
      default:
        return -1;
    };
}
static CK_MECHANISM_PTR hash_mechanism (SRP_HashAlgorithm alg) {
	static CK_MECHANISM ckm_sha_1  = { CKM_SHA_1,  NULL, 0 };
	static CK_MECHANISM ckm_sha224 = { CKM_SHA224, NULL, 0 };
	static CK_MECHANISM ckm_sha256 = { CKM_SHA256, NULL, 0 };
	static CK_MECHANISM ckm_sha384 = { CKM_SHA384, NULL, 0 };
	static CK_MECHANISM ckm_sha512 = { CKM_SHA512, NULL, 0 };
	switch (alg) {
	case SRP_SHA1:
		return &ckm_sha_1;
	case SRP_SHA224:
		return &ckm_sha224;
	case SRP_SHA256:
		return &ckm_sha256;
	case SRP_SHA384:
		return &ckm_sha384;
	case SRP_SHA512:
		return &ckm_sha512;
	default:
		return NULL;
	}
}

static void hash_update_bignum (SRP_HashAlgorithm alg, HashCTX *hctx, BIGNUM *n) {
	unsigned char bytes_n [5000];
	int len_n;
	len_n = BN_num_bytes (n);
	assert (len_n <= sizeof (bytes_n));
	BN_bn2bin (n, bytes_n);
	hash_update (alg, hctx, bytes_n, len_n);
}

static BIGNUM *H_nn (SRP_HashAlgorithm alg, BIGNUM *n1, BIGNUM *n2) {
	unsigned char hbuf [SHA512_DIGEST_LENGTH];
	HashCTX hctx;
	int hashlen;
	//
	// Sizes and safety checks
	hashlen  = hash_length (alg);
	assert (hashlen  <= sizeof (hbuf));
	//
	// Compute the hash
	hash_init          (alg, &hctx);
	hash_update_bignum (alg, &hctx, n1);
	hash_update_bignum (alg, &hctx, n2);
	hash_final         (alg, &hctx, hbuf);
	//
	// Turn the hash into a BIGNUM
	// This returns NULL on failure, which is what the caller expects
	return BN_bin2bn (hbuf, hashlen, NULL);
}


CK_RV hex2bin (CK_BYTE_PTR binbuf, const char *hexstr) {
	uint8_t c1, c2;
	while (*hexstr) {
		c1 = *hexstr++;
		if ((c1 >= '0') && (c1 <= '9')) {
			c1 -= '0';
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			c1 -= 'A' - 10;
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			c1 -= 'a' - 10;
		} else {
			return CKR_DOMAIN_PARAMS_INVALID;
		}
		assert (c1 <= 15);
		c2 = *hexstr++;	// May be '\0', drops out below
		if ((c2 >= '0') && (c2 <= '9')) {
			c2 -= '0';
		} else if ((c2 >= 'A') && (c2 <= 'F')) {
			c2 -= 'A' - 10;
		} else if ((c2 >= 'a') && (c2 <= 'f')) {
			c2 -= 'a' - 10;
		} else {
			return CKR_DOMAIN_PARAMS_INVALID;
		}
		assert (c2 <= 15);
		*binbuf++ = (c1 << 4) | c2;
	}
	return CKR_OK;
}


/*******************************************************************************
 *
 *  Exported Functions
 *
 ******************************************************************************/


CK_RV srp11_create_new_keys (
		CK_SESSION_HANDLE p11ses,
		CK_ATTRIBUTE_PTR attrs, CK_ULONG numattrs,
		SRP_NGType ng_type, const char *n_hex, const char *g_hex,
		CK_OBJECT_HANDLE_PTR srp11pub, CK_OBJECT_HANDLE_PTR srp11priv) {
	CK_RV ckrv = CKR_OK;
	CK_OBJECT_CLASS pubobjcls = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS prvobjcls = CKO_PRIVATE_KEY;
	CK_KEY_TYPE dhkeytp = CKK_DH;
	CK_BYTE prime [5000], base  [1000];
	CK_ULONG primelen, baselen;
	CK_BBOOL true  = CK_TRUE ;
	CK_ATTRIBUTE pubtmpl [2 + MAXNUM_EXTRA_ATTRS] = {
		{ CKA_PRIME, prime, -1 },	// [0].ulValueLen filled below
		{ CKA_BASE, base, -1 },		// [1].ulValueLen filled below
		//GEND// { CKA_CLASS, &pubobjcls, sizeof(pubobjcls) },
		//GEND// { CKA_KEY_TYPE, &dhkeytp, sizeof(dhkeytp) },
		//USER// { CKA_TOKEN, &true, sizeof(true) },
		//USER// { CKA_LABEL, label, sizeof(label)-1 },
		//GEND// { CKA_VALUE, value, sizeof(value) }
	};
	CK_ATTRIBUTE prvtmpl [1 + MAXNUM_EXTRA_ATTRS] = {
		//GEND// { CKA_CLASS, &prvobjcls, sizeof(prvobjcls) },
		//GEND// { CKA_KEY_TYPE, &dhkeytp, sizeof(dhkeytp) },
		{ CKA_DERIVE, &true, sizeof(true) },
		//USER// { CKA_SENSITIVE, &true, sizeof(true) },
		//USER// { CKA_TOKEN, &true, sizeof(true) },
		//USER// { CKA_LABEL, label, sizeof(label)-1 },
		//USER// { CKA_SUBJECT, subject, sizeof(subject) },
		//USER// { CKA_ID, id, sizeof(id) },
		//GEND// { CKA_PRIME, prime, sizeof(prime) },
		//GEND// { CKA_BASE, base, sizeof(base) },
		//GEND// { CKA_VALUE, value, sizeof(value) }
	};
	CK_ULONG pubtmplsz = sizeof (pubtmpl) / sizeof (CK_ATTRIBUTE) - MAXNUM_EXTRA_ATTRS;
	CK_ULONG prvtmplsz = sizeof (prvtmpl) / sizeof (CK_ATTRIBUTE) - MAXNUM_EXTRA_ATTRS;
	CK_MECHANISM mech = { CKM_DH_PKCS_KEY_PAIR_GEN, NULL, 0 };
	//
	// If a standard ng_type is supplied, dig up its hex codes
	if (ng_type != SRP_NG_CUSTOM) {
		if ((n_hex != NULL) || (g_hex != NULL)) {
			return CKR_ARGUMENTS_BAD;
		}
		n_hex = global_Ng_constants [ng_type].n_hex;
		g_hex = global_Ng_constants [ng_type].g_hex;
	}
	//
	// Ensure that the hex input is not oversized or odd-length
	if ((n_hex == NULL) || (g_hex == NULL)) {
		return CKR_ARGUMENTS_BAD;
	}
	primelen = strlen (n_hex);
	baselen  = strlen (g_hex);
	if ((primelen & 0x0001) || (baselen & 0x0001)) {
		return CKR_ARGUMENTS_BAD;
	}
	primelen >>= 1;
	baselen  >>= 1;
	if ((primelen > sizeof (prime)) ||
	    (baselen  > sizeof (base ))) {
		return CKR_DATA_LEN_RANGE;
	}
	//
	// Ensure that the attributes fit in the public and private templates
	if ((numattrs > 0) && (attrs == NULL)) {
		return CKR_ARGUMENTS_BAD;
	}
	if (numattrs > MAXNUM_EXTRA_ATTRS) {
		return CKR_BUFFER_TOO_SMALL;
	}
	//
	// Translate n_hex and g_hex to the DH group's prime and base
	ckrv = hex2bin (prime, n_hex);
	if (ckrv != CKR_OK) return ckrv;
	ckrv = hex2bin (base,  g_hex);
	if (ckrv != CKR_OK) return ckrv;
	//
	// Attach the given attributes to public and private templates
	// PKCS #11 ensures that no bad (or double?) entries exist
	assert (pubtmpl [0].type == CKA_PRIME);
	assert (pubtmpl [1].type == CKA_BASE );
	pubtmpl [0].ulValueLen = primelen;
	pubtmpl [1].ulValueLen = baselen ;
	if (attrs != NULL) {
		memcpy (pubtmpl + pubtmplsz, attrs,
					sizeof (CK_ATTRIBUTE) * numattrs);
		pubtmplsz += numattrs;
		memcpy (prvtmpl + prvtmplsz, attrs,
					sizeof (CK_ATTRIBUTE) * numattrs);
		prvtmplsz += numattrs;
	}
	return C_GenerateKeyPair (p11ses, &mech,
				pubtmpl, pubtmplsz,
				prvtmpl, prvtmplsz,
				srp11pub, srp11priv);
}


CK_RV srp11_regenerate_pubkey (CK_SESSION_HANDLE p11ses,
				CK_OBJECT_HANDLE srp11priv,
				CK_ATTRIBUTE_PTR attrs, CK_ULONG numattrs,
				CK_OBJECT_HANDLE_PTR srp11pub) {
	CK_RV ckrv = CKR_OK;
	CK_BYTE tmpkey [5000];
	CK_BBOOL true = CK_TRUE;
	CK_MECHANISM drvmech = { CKM_DH_PKCS_DERIVE, tmpkey, 0 };
	CK_OBJECT_CLASS drvobjcls = CKO_SECRET_KEY;
	CK_KEY_TYPE drvkeytp = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE attr_modlen_base [2] = {
		{ CKA_PRIME, NULL, 0 },
		{ CKA_BASE, &tmpkey, sizeof (tmpkey) } };
	CK_ATTRIBUTE drvtmpl [4 + MAXNUM_EXTRA_ATTRS] = {
		//DEFAULT// { CKA_TOKEN, &false, sizeof (false) },
		//DEFAULT// { CKA_SENSITIVE, &false, sizeof (false) },
		{ CKA_EXTRACTABLE, &true, sizeof (true) },
		{ CKA_CLASS, &drvobjcls, sizeof (drvobjcls) },
		{ CKA_KEY_TYPE, &drvkeytp, sizeof (drvkeytp) },
		{ CKA_VALUE_LEN, &attr_modlen_base [0].ulValueLen, sizeof (CK_ULONG) },
	};
	CK_ULONG drvtmplsz = sizeof (drvtmpl) / sizeof (CK_ATTRIBUTE) - MAXNUM_EXTRA_ATTRS;
	//
	// Retrieve the modulus length from the private key in PKCS #11
	ckrv = C_GetAttributeValue (p11ses, srp11priv, attr_modlen_base, 2);
	if (ckrv != CKR_OK) return ckrv;
	drvmech.ulParameterLen = attr_modlen_base [1].ulValueLen;
	//
	// Clone in the additional attributes
	if ((numattrs > 0) && (attrs == NULL)) {
		return CKR_ARGUMENTS_BAD;
	}
	if (numattrs > MAXNUM_EXTRA_ATTRS) {
		return CKR_BUFFER_TOO_SMALL;
	}
	if (attrs != NULL) {
		memcpy (drvtmpl + drvtmplsz, attrs, numattrs * sizeof (CK_ATTRIBUTE));
		drvtmplsz += numattrs;
	}
	//
	// Derive the public key from the private key
	ckrv = C_DeriveKey (p11ses, &drvmech, srp11priv,
				drvtmpl, drvtmplsz,
				srp11pub);
	if (ckrv != CKR_OK) return ckrv;
	//
	// Finally, return the last result from PKCS #11, so CKR_OK
	return ckrv;
}


CK_RV srp11_retrieve_pubkey (CK_SESSION_HANDLE p11ses,
				CK_OBJECT_HANDLE srp11pub,
				unsigned char **bytes_pubkey, int *len_pubkey) {
	CK_RV ckrv = CKR_OK;
	CK_ATTRIBUTE attr = { CKA_VALUE, NULL, 5000 };
	//
	// Retrieve the length of the value
	ckrv = C_GetAttributeValue (p11ses, srp11pub, &attr, 1);
	if (ckrv != CKR_OK) return ckrv;
	//
	// Allocate memory for the public key bytes
	attr.pValue = malloc (attr.ulValueLen);
	if (attr.pValue == NULL) {
		return CKR_HOST_MEMORY;
	}
	//
	// Retrieve the public key value
	ckrv = C_GetAttributeValue (p11ses, srp11pub, &attr, 1);
	if (ckrv != CKR_OK) {
		free (attr.pValue);
		return ckrv;
	}
	//
	// Return the desired result
	*bytes_pubkey = attr.pValue;
	*len_pubkey = attr.ulValueLen;
	return CKR_OK;
}


/* Internal function.  Compute bn_H_s_hochP = H(s)^P in BIGNUM format.
 *
 * The computation must be done over PKCS #11, using the private key P.
 * The result prepares for computation of v = p^bn_H_s_hochP and of S.
 *
 * Input parameters include:
 *  - bn_p holding the public key
 *  - bn_m holding the modulus
 *  - bytes_s/len_s holding the data to be hashed
 *  - hash_alg holding the SRP_xxx hash identifier
 *
 * The result will be stored in a pre-allocated BIGNUM structure.
 */
static CK_RV compute_H_s_hochP (
				CK_SESSION_HANDLE p11ses,
				CK_OBJECT_HANDLE srp11priv,
				BIGNUM *bn_p,
				BIGNUM *bn_m,
				unsigned char *bytes_s, int len_s, 
				SRP_HashAlgorithm hash_alg,
				BIGNUM *bn_H_s_hochP) {
	CK_RV ckrv = CKR_OK;
	CK_BBOOL false = CK_FALSE;
	CK_BBOOL true = CK_TRUE;
	CK_BYTE H_s [SHA512_DIGEST_LENGTH];
	CK_MECHANISM digmech;
	int hashlen = hash_length (hash_alg);
	CK_ULONG hashlen11;
	CK_ULONG modlen = BN_num_bytes (bn_m);
	CK_BYTE tmpkey [5000];
	CK_ATTRIBUTE attr;
	//
	// Sizes and safety checks
	assert (bn_m != NULL);
	assert (bn_p != NULL);
	assert (bn_H_s_hochP != NULL);
	assert (len_s >= hashlen);
	assert (hashlen <= sizeof (H_s));
	assert (modlen <= sizeof (tmpkey));
	//
	// Determine H(s) and store it in H_s; take bytes beyond random
	// that was just filled into account; it might be used for things
	// like pinning.
	ckrv = C_DigestInit (p11ses, hash_mechanism (hash_alg));
	if (ckrv != CKR_OK) return ckrv;
	hashlen11 = hashlen;
	ckrv = C_Digest (p11ses, (CK_BYTE_PTR) bytes_s, len_s, H_s, &hashlen11);
	if (ckrv != CKR_OK) return ckrv;
	assert (hashlen == hashlen11);
	//
	// Now use C_DeriveKey() to construct H(s)^P in the token,
	// thus employing the private key P without taking it off the token;
	// the result is a session key that will be taken off 
	CK_MECHANISM drvmech = { CKM_DH_PKCS_DERIVE, H_s, hashlen11 };
	CK_OBJECT_CLASS drvobjcls = CKO_SECRET_KEY;
	CK_KEY_TYPE drvkeytp = CKK_GENERIC_SECRET;
	CK_OBJECT_HANDLE key_H_s_hochP = CK_INVALID_HANDLE;
	CK_ATTRIBUTE drvtmpl [] = {
		//DEFAULT// { CKA_TOKEN, &false, sizeof (false) },
		//DEFAULT// { CKA_SENSITIVE, &false, sizeof (false) },
		{ CKA_EXTRACTABLE, &true, sizeof (true) },
		{ CKA_CLASS, &drvobjcls, sizeof (drvobjcls) },
		{ CKA_KEY_TYPE, &drvkeytp, sizeof (drvkeytp) },
		{ CKA_VALUE_LEN, &modlen, sizeof (modlen) },
	};
	CK_ULONG drvtmplsz = sizeof (drvtmpl) / sizeof (CK_ATTRIBUTE);
	ckrv = C_DeriveKey (p11ses, &drvmech, srp11priv,
				drvtmpl, drvtmplsz,
				&key_H_s_hochP);
	if (ckrv != CKR_OK) return ckrv;
	//
	// Extract the constructed value H(s)^P from PKCS #11
	attr.type = CKA_VALUE;
	attr.pValue = tmpkey;
	attr.ulValueLen = sizeof (tmpkey);
	ckrv = C_GetAttributeValue (p11ses, key_H_s_hochP, &attr, 1);
	if (ckrv != CKR_OK) goto cleanup;
	if (attr.ulValueLen != modlen) {
		ckrv = CKR_DOMAIN_PARAMS_INVALID;
		goto cleanup;
	}
	ckrv = C_DestroyObject (p11ses, key_H_s_hochP);
	key_H_s_hochP = CK_INVALID_HANDLE;
	if (ckrv != CKR_OK) return ckrv;
	if (BN_bin2bn (tmpkey, attr.ulValueLen, bn_H_s_hochP) == NULL) {
		ckrv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	//
	// This is a one-shot function, so no state is kept.  So cleanup!
	//
cleanup:
	if (key_H_s_hochP != CK_INVALID_HANDLE) {
		if (C_DestroyObject (p11ses, key_H_s_hochP) != CKR_OK) {
			fprintf (stderr, "Failed to cleanup session key_H_s_hochP after CK_RV 0x%08x\n", ckrv);
		}
		key_H_s_hochP = CK_INVALID_HANDLE;
	}
	return ckrv;
}


CK_RV srp11_create_salted_verification_key (
				CK_SESSION_HANDLE p11ses,
				CK_OBJECT_HANDLE srp11priv,
				unsigned char *bytes_pubkey, int len_pubkey,
				SRP_HashAlgorithm hash_alg,
				unsigned char **bytes_s, int *len_s, 
				unsigned char **bytes_v, int *len_v) {
	CK_RV ckrv = CKR_OK;
	CK_BBOOL false = CK_FALSE;
	CK_BBOOL true = CK_TRUE;
	int hashlen = hash_length (hash_alg);
	CK_BYTE tmpkey [5000];
	CK_ATTRIBUTE attr;
	BN_CTX *bnctx = NULL;
	BIGNUM *bn_H_s_hochP = NULL;
	BIGNUM *bn_p = NULL;
	BIGNUM *bn_m = NULL;
	BIGNUM *bn_v = NULL;
	//
	// Sizes and safety checks
	assert (bytes_s != NULL);
	assert (bytes_v != NULL);
	assert (len_s   != NULL);
	assert (len_v   != NULL);
	//
	// Prepare the salt to receive hashlen random bytes
	if (hashlen == -1) {
		return CKR_ARGUMENTS_BAD;
	}
	if (!*bytes_s) {
		*bytes_s = malloc (hashlen);
		if (*bytes_s == NULL) {
			return CKR_HOST_MEMORY;
		}
		*len_s = hashlen;
	}
	if (*len_s < hashlen) {
		return CKR_BUFFER_TOO_SMALL;
	}
	//
	// Fill random bytes in the initial hashlen bytes of the salt
	//TODO// Perhaps generate at least 256 bits?
	ckrv = C_GenerateRandom (p11ses, (CK_BYTE_PTR) *bytes_s, hashlen);
	if (ckrv != CKR_OK) return ckrv;
	//
	// Construct the public key p from the provides bytes_pubkey / len_pubkey
	bn_p = BN_bin2bn (bytes_pubkey, len_pubkey, NULL);
	if (bn_p == NULL) {
		ckrv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	//
	// Retrieve the modulus m (with handle srp11priv) from PKCS #11
	attr.type = CKA_PRIME;
	attr.pValue = tmpkey;
	attr.ulValueLen = sizeof (tmpkey);
	ckrv = C_GetAttributeValue (p11ses, srp11priv, &attr, 1);
	if (ckrv != CKR_OK) goto cleanup;
	bn_m = BN_bin2bn (tmpkey, attr.ulValueLen, NULL);
	if (bn_m == NULL) {
		ckrv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	//
	// Compute bn_H_s_hochP = H(s)^p as a BIGNUM
	bn_H_s_hochP = BN_new ();
	if (bn_H_s_hochP == NULL) {
		ckrv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	ckrv = compute_H_s_hochP (p11ses, srp11priv,
				bn_p, bn_m,
				*bytes_s, *len_s, hash_alg,
				bn_H_s_hochP);
	if (ckrv != CKR_OK) return ckrv;
	//
	// Raise p to H(s)^P to find v'' = p ^ (H(s)^P)
	bnctx = BN_CTX_new ();
	bn_v = BN_new ();
	if ((bnctx == NULL) || (bn_v == NULL)) {
		ckrv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	//
	// bn_v := ( bn_p ^ bn_H_s_hochP ) % bn_m   [in context bnctx]
	if (BN_mod_exp (bn_v, bn_p, bn_H_s_hochP, bn_m, bnctx) != 1) {
		fprintf (stderr, "Crypto error %l in BN_mod_exp()\n",
					ERR_get_error ());
		ckrv = CKR_GENERAL_ERROR;
		goto cleanup;
	}
	//
	// Export the bytes of the verifier to the caller
	*len_v = BN_num_bytes(bn_v);
	*bytes_v = malloc (*len_v);
	if (*bytes_v == NULL) {
		*len_v = 0;
		ckrv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	BN_bn2bin (bn_v, (unsigned char *) *bytes_v);
	//
	// This is a one-shot function, so no state is kept.  So cleanup!
	//
cleanup:
	if (bn_v != NULL) {
		BN_free (bn_v);
		bn_v = NULL;
	}
	if (bn_m != NULL) {
		BN_free (bn_m);
		bn_m = NULL;
	}
	if (bn_p != NULL) {
		BN_free (bn_p);
		bn_p = NULL;
	}
	if (bn_H_s_hochP != NULL) {
		BN_free (bn_H_s_hochP);
		bn_H_s_hochP = NULL;
	}
	if (bnctx != NULL) {
		BN_CTX_free (bnctx);
		bnctx = NULL;
	}
	return ckrv;
}


/******************************************************************************/


CK_RV srp11_user_new (
				CK_SESSION_HANDLE p11ses,
				CK_OBJECT_HANDLE srp11pub,
				CK_OBJECT_HANDLE srp11priv,
				SRP_HashAlgorithm alg,
				struct SRP11User **user) {
	CK_RV ckrv = CKR_OK;
	CK_BYTE pubkey  [5000];
	CK_BYTE modulus [5000];
	CK_BYTE base    [1000];
	CK_ATTRIBUTE pubmodbas [] = {
		{ CKA_VALUE, pubkey , sizeof (pubkey ) },
		{ CKA_PRIME, modulus, sizeof (modulus) },
		{ CKA_BASE,  base   , sizeof (base   ) } };
	//
	// Initialise
	assert (user != NULL);
	*user = NULL;
	//
	// Allocate and clear the return structure
	*user = malloc (sizeof (struct SRP11User));
	if (*user == NULL) {
		ckrv = CKR_HOST_MEMORY;
		goto failure;
	}
	bzero (*user, sizeof (struct SRP11User));
	//
	// Retrieve prime, base and modulus from srp11pub in PKCS #11
	ckrv = C_GetAttributeValue (p11ses, srp11pub, pubmodbas, 3);
	if (ckrv != CKR_OK) goto failure;
	//
	// Map the prime, base and modulus to a BIGNUM
	(*user)->pubkey  = BN_bin2bn (pubkey , pubmodbas [0].ulValueLen, NULL);
	(*user)->modulus = BN_bin2bn (modulus, pubmodbas [1].ulValueLen, NULL);
	(*user)->base    = BN_bin2bn (base   , pubmodbas [2].ulValueLen, NULL);
	if (((*user)->pubkey  == NULL) ||
	    ((*user)->modulus == NULL) ||
	    ((*user)->base    == NULL)) {
		ckrv = CKR_HOST_MEMORY;
		goto failure;
	}
	//
	// Allocate additional variables needed for the protocol flow
	(*user)->a = BN_new ();
	(*user)->A = BN_new ();
	if (((*user)->a == NULL) ||
	    ((*user)->A == NULL)) {
		ckrv = CKR_HOST_MEMORY;
		goto failure;
	}
	//
	// Fill the rest of the user structure
	(*user)->hash_alg = alg;
	(*user)->p11ses = p11ses;
	(*user)->srp11priv = srp11priv;

	return CKR_OK;

failure:
	if (*user != NULL) {
		srp11_user_delete (*user);
		*user = NULL;
	}
	return ckrv;
}


void srp11_user_delete (struct SRP11User *user) {
	if (user != NULL) {
		if (user->a != NULL) {
			BN_free (user->a);
			user->a = NULL;
		}
		if (user->A != NULL) {
			BN_free (user->A);
			user->A = NULL;
		}
		if (user->base != NULL) {
			BN_free (user->base);
			user->base = NULL;
		}
		if (user->modulus != NULL) {
			BN_free (user->modulus);
			user->modulus = NULL;
		}
		if (user->pubkey != NULL) {
			BN_free (user->pubkey);
			user->pubkey = NULL;
		}
		user->srp11priv = CK_INVALID_HANDLE;
		user->p11ses = CK_INVALID_HANDLE;
		user->authenticated = 0;
		bzero (user->H_AMK, sizeof (user->H_AMK));
		bzero (user->session_key, sizeof (user->session_key));
		free (user);
		user = NULL;
	}
}


CK_RV srp11_user_start_authentication (
			struct SRP11User *user,
			unsigned char **bytes_A, int *len_A) {
	int len_a;
	CK_RV ckrv = CKR_OK;
	int retval;
	CK_BYTE bytes_a [SHA512_DIGEST_LENGTH];
	BN_CTX *bnctx;
	//
	// Sizes and safety checks
	assert (bytes_A != NULL);
	assert (len_A != NULL);
	len_a = hash_length (user->hash_alg);
	assert (len_a <= sizeof (bytes_a));
	*bytes_A = NULL;
	*len_A = 0;
	//
	// Generate the random value "a"
	//TODO// Perhaps generate at least 256 bits?
	ckrv = C_GenerateRandom (user->p11ses, bytes_a, len_a);
	if (ckrv != CKR_OK) return ckrv;
	//
	// Store "a" in the user object
	assert (user->a != NULL);
	user->a = BN_bin2bn (bytes_a, len_a, user->a);
	if (user->a == NULL) {
		return CKR_HOST_MEMORY;
	}
	//
	// Produce A = g^a or in user fields, A = base^a % modulus
	assert (user->A != NULL);
	bnctx = BN_CTX_new ();
	if (bnctx == NULL) {
		return CKR_HOST_MEMORY;
	}
	retval = BN_mod_exp (user->A, user->base, user->a, user->modulus, bnctx);
	BN_CTX_free (bnctx);
	if (retval != 1) {
		fprintf (stderr, "Crypto error %l in BN_mod_exp()\n",
					ERR_get_error ());
		return CKR_GENERAL_ERROR;
	}
	//
	// Store A in the output variables
	*len_A = BN_num_bytes (user->A);
	*bytes_A = malloc (*len_A);
	if (*bytes_A == NULL) {
		*len_A = 0;
		return CKR_HOST_MEMORY;
	}
	BN_bn2bin (user->A, *bytes_A);
	//
	// Return and prosper
	return CKR_OK;
}


/* Internal function.  In a manner that is reminiscent of BN_mod_exp, compute
 * the modular exponentiation function, where the exponent is a DH private key.
 * This is done through the PKCS #11 interface to protect the private key.
 *
 * Inputs are:
 *  - p11ses is the PKCS #11 session handle
 *  - result will hold the result base^exp_P % mod_P
 *  - base is the base factor to be raised to the private power
 *  - srp11priv is the private DH key from which  exp_P and mod_P will be taken
 *
 * The two BIGNUM values result and base may coincide.
 *
 * The function returns a value in CK_RV, as any PKCS #11 function does; this
 * is a diversion from the wish to mimic BN_mod_exp().
 */
CK_RV p11_mod_exp (CK_SESSION_HANDLE p11ses,
				BIGNUM *result, BIGNUM *base,
				CK_OBJECT_HANDLE srp11priv) {
	CK_RV ckrv = CKR_OK;
	CK_OBJECT_HANDLE p11outcome = CK_INVALID_HANDLE;
	CK_BBOOL true = CK_TRUE;
	CK_BYTE tmpkey [5000];
	CK_MECHANISM drvmech = { CKM_DH_PKCS_DERIVE, tmpkey, 0 };
	CK_OBJECT_CLASS drvobjcls = CKO_SECRET_KEY;
	CK_KEY_TYPE drvkeytp = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE attr_modlen = { CKA_PRIME, NULL, sizeof (tmpkey) };
	CK_ATTRIBUTE attr_outcome = { CKA_VALUE, tmpkey, sizeof (tmpkey) };
	CK_ATTRIBUTE drvtmpl [] = {
		//DEFAULT// { CKA_TOKEN, &false, sizeof (false) },
		//DEFAULT// { CKA_SENSITIVE, &false, sizeof (false) },
		{ CKA_EXTRACTABLE, &true, sizeof (true) },
		{ CKA_CLASS, &drvobjcls, sizeof (drvobjcls) },
		{ CKA_KEY_TYPE, &drvkeytp, sizeof (drvkeytp) },
		{ CKA_VALUE_LEN, &attr_modlen.ulValueLen, sizeof (CK_ULONG) } };
	CK_ULONG drvtmplsz = sizeof (drvtmpl) / sizeof (CK_ATTRIBUTE);
	//
	// Retrieve the size of the modulus, i.o.w. the size of the output
	ckrv = C_GetAttributeValue (p11ses, srp11priv, &attr_modlen, 1);
	if (ckrv != CKR_OK) return ckrv;
	//
	// Fill the tmpkey field with the base
	drvmech.ulParameterLen = BN_num_bytes (base);
	if (drvmech.ulParameterLen > sizeof (tmpkey)) {
		return CKR_DOMAIN_PARAMS_INVALID;
	}
	BN_bn2bin (base, tmpkey);
	//
	// Use the DH key derivation mechanism to raise to the private key
	ckrv = C_DeriveKey (p11ses, &drvmech, srp11priv,
				drvtmpl, drvtmplsz,
				&p11outcome);
	if (ckrv != CKR_OK) return ckrv;
	//
	// Retrieve the outcome into tmpkey and discard temporary p11outcome
	ckrv = C_GetAttributeValue (p11ses, p11outcome, &attr_outcome, 1);
	if (C_DestroyObject (p11ses, p11outcome) != CKR_OK) {
		fprintf (stderr, "Failed to destroy temporary session key during error 0x%08x\n", ckrv);
	}
	if (ckrv != CKR_OK) return ckrv;
	//
	// Pass the value in tmpkey over to the result BIGNUM
	result = BN_bin2bn (tmpkey, attr_outcome.ulValueLen, result);
	if (result == NULL) {
		return CKR_HOST_MEMORY;
	}
	return CKR_OK;;
}

CK_RV srp11_user_process_challenge (
			struct SRP11User *user, 
			unsigned char *bytes_s, int len_s, 
			unsigned char *bytes_B, int len_B,
			unsigned char **bytes_M, int *len_M) {
	CK_RV ckrv = CKR_OK;
	BN_CTX *bnctx = NULL;
	HashCTX hctx;
	BIGNUM *bn_H_s_hochP = NULL;
	BIGNUM *bn_v = NULL;
	BIGNUM *bn_k = NULL;
	BIGNUM *bn_B = NULL;
	BIGNUM *bn_u = NULL;
	BIGNUM *bn_S = NULL;
	BIGNUM *bn_1 = NULL;
	BIGNUM *bn_2 = NULL;
	int hashlen;
	int modlen;
	//
	// Sizes and safety checks
	assert (bytes_M != NULL);
	assert (len_M != NULL);
	*bytes_M = NULL;
	*len_M = 0;
	//
	// Input parameter correctness
	hashlen = hash_length (user->hash_alg);
	if (len_s < hashlen) {
		return CKR_DOMAIN_PARAMS_INVALID;
	}
	modlen = BN_num_bytes (user->modulus);
	if (len_B != modlen) {
		return CKR_DOMAIN_PARAMS_INVALID;
	}
	//
	// Recompute H_s_hochP = H(s)^P as bn_H_s_hochP
	bn_H_s_hochP = BN_new ();
	if (bn_H_s_hochP == NULL) {
		return CKR_HOST_MEMORY;
	}
	ckrv = compute_H_s_hochP (user->p11ses, user->srp11priv,
				user->pubkey, user->modulus,
				bytes_s, len_s, user->hash_alg,
				bn_H_s_hochP);
	if (ckrv != CKR_OK) {
		goto cleanup;
	}
	//
	// Recompute verifier v = p ^ H(s)^P as bn_v
	// Variables: bn_v := ( base ^ bn_H_s_hochP ) % modulus [in context bnctx]
	bn_v = BN_new ();
	bnctx = BN_CTX_new ();
	if ((bn_v == NULL) || (bnctx == NULL)) {
		ckrv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	if (BN_mod_exp (bn_v, user->pubkey, bn_H_s_hochP, user->modulus, bnctx) != 1) {
		fprintf (stderr, "Crypto error %l in BN_mod_exp()\n",
					ERR_get_error ());
		ckrv = CKR_GENERAL_ERROR;
		goto cleanup;
	}
	//
	// Compute k = H(N,g) -- this is specific for SRP 6a
	//                    -- it was 3 in legacy SRP 6
	//                    -- it was 1 (or absent) in SRP 3
	bn_k = H_nn (user->hash_alg, user->modulus, user->base);
	if (bn_k == NULL) {
		ckrv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	//
	// Compute u = H(A,B) -- this is specific for SRP 6
	//                    -- it was server-generated random in SRP 3
	bn_B = BN_bin2bn (bytes_B, len_B, NULL);
	if (bn_B == NULL) {
		ckrv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	bn_u = H_nn (user->hash_alg, user->A, bn_B);
	if (bn_u == NULL) {
		ckrv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	//
	// Compute S = (B-kv)^a * (((B-kv)^u)^(H(s)^P))^P
	//  1. bn_1 := bn_v * bn_k == kv
	//  2. bn_2 := bn_B - bn_1 == B-kv
	//  3. bn_1 := bn_2^a == (B-kv)^a
	//  4. bn_2 := bn_2^a == (B-kv)^u
	//  5. bn_2 := bn_2^bn_H_s_hochP = ((B-kv)^u)^(H(s)^P)
	//  6. bn_2 := bn_2^P = (((B-kv)^u)^(H(s)^P))^P		[via PKCS #11]
	//  7. bn_S := bn_1 * bn_2 == (B-kv)^u * (((B-kv)^u)^(H(s)^P))^P
	bn_S = BN_new ();
	bn_1 = BN_new ();
	bn_2 = BN_new ();
	if ((bn_S == NULL) || (bn_1 == NULL) || (bn_2 == NULL)) {
		ckrv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	int ok = 1;
	//  1. bn_1 := bn_v * bn_k == kv
	ok = ok && (BN_mod_mul (bn_1, bn_v, bn_k,    user->modulus, bnctx) == 1);
	//  2. bn_2 := bn_B - bn_1 == B-kv
	ok = ok && (BN_mod_sub (bn_2, bn_B, bn_1,    user->modulus, bnctx) == 1);
	//  3. bn_1 := bn_2^a == (B-kv)^a
	ok = ok && (BN_mod_exp (bn_1, bn_2, user->a, user->modulus, bnctx) == 1);
	//  4. bn_2 := bn_2^a == (B-kv)^u
	ok = ok && (BN_mod_exp (bn_2, bn_2, bn_u,    user->modulus, bnctx) == 1);
	//  5. bn_2 := bn_2^bn_H_s_hochP = ((B-kv)^u)^(H(s)^P)
	ok = ok && (BN_mod_exp (bn_2, bn_2, bn_H_s_hochP, user->modulus, bnctx) == 1);
	//  6. bn_2 := bn_2^P = (((B-kv)^u)^(H(s)^P))^P		[via PKCS #11]
	if (ok) {
		ckrv = p11_mod_exp (user->p11ses, bn_2, bn_2, user->srp11priv);
		if (ckrv != CKR_OK) {
			goto cleanup;
		}
	}
	//  7. bn_S := bn_1 * bn_2 == (B-kv)^u * (((B-kv)^u)^(H(s)^P))^P
	ok = ok && (BN_mod_mul (bn_S, bn_1, bn_2,    user->modulus, bnctx) == 1);
	if (!ok) {
		fprintf (stderr, "Crypto error %l in user computation of S()\n",
					ERR_get_error ());
		ckrv = CKR_GENERAL_ERROR;
		goto cleanup;
	}
	//
	// Compute K = H(S)
	// Note that K is stored as user->session_key [0..hashlen>
	hash_init          (user->hash_alg, &hctx);
	hash_update_bignum (user->hash_alg, &hctx, bn_S);
	hash_final         (user->hash_alg, &hctx, user->session_key);
	//
	// Setup the space to return M
	*bytes_M = malloc (hashlen);
	if (*bytes_M == NULL) {
		ckrv = CKR_HOST_MEMORY;
		goto cleanup;
	}
	*len_M = hashlen;
	//
	// Compute M = H(A,B,K) to validate user to the service
	hash_init          (user->hash_alg, &hctx);
	hash_update_bignum (user->hash_alg, &hctx, user->A);
	hash_update_bignum (user->hash_alg, &hctx, bn_B);
	hash_update        (user->hash_alg, &hctx, user->session_key, hashlen);
	hash_final         (user->hash_alg, &hctx, *bytes_M);
	//
	// Compute H_AMK = H (A,M,K) for future validation of service to user
	hash_init          (user->hash_alg, &hctx);
	hash_update_bignum (user->hash_alg, &hctx, user->A);
	hash_update        (user->hash_alg, &hctx, bytes_M,           hashlen);
	hash_update        (user->hash_alg, &hctx, user->session_key, hashlen);
	hash_final         (user->hash_alg, &hctx, user->H_AMK);
	//
	// We allocated several intermediate-value buffers; clean them up.
cleanup:
	if (ckrv != CKR_OK) {
		if (*bytes_M) {
			free (*bytes_M);
			*bytes_M = NULL;
		}
		*len_M = 0;
	}
	if (bn_2 != NULL) {
		BN_free (bn_2);
		bn_2 = NULL;
	}
	if (bn_1 != NULL) {
		BN_free (bn_1);
		bn_1 = NULL;
	}
	if (bn_S != NULL) {
		BN_free (bn_S);
		bn_S = NULL;
	}
	if (bn_u != NULL) {
		BN_free (bn_u);
		bn_u = NULL;
	}
	if (bn_B != NULL) {
		BN_free (bn_B);
		bn_B = NULL;
	}
	if (bn_k != NULL) {
		BN_free (bn_k);
		bn_k = NULL;
	}
	if (bn_v != NULL) {
		BN_free (bn_v);
		bn_v = NULL;
	}
	if (bn_H_s_hochP != NULL) {
		BN_free (bn_H_s_hochP);
		bn_H_s_hochP = NULL;
	}
	if (bnctx != NULL) {
		BN_CTX_free (bnctx);
		bnctx = NULL;
	}
	return ckrv;
}


int srp11_user_has_authenticated_service (struct SRP11User *user) {
	return user->authenticated;
}



#if 0

const unsigned char * srp11_user_get_session_key( struct SRP11User * usr, int * key_length )
{
    if (key_length)
        *key_length = hash_length( usr->hash_alg );
    return usr->session_key;
}


int                   srp11_user_get_session_key_length( struct SRP11User * usr )
{
    return hash_length( usr->hash_alg );
}




void srp11_user_verify_service( struct SRP11User * usr, const unsigned char * bytes_HAMK )
{
    if ( memcmp( usr->H_AMK, bytes_HAMK, hash_length(usr->hash_alg) ) == 0 )
        usr->authenticated = 1;
}
#endif
