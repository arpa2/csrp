#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <unistd.h>

#include <pkcs11.h>


#include "srp.h"
#include "srp11.h"


#define NITER          100
#define TEST_HASH      SRP_SHA1
#define TEST_NG        SRP_NG_1024

unsigned long long get_usec()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return (((unsigned long long)t.tv_sec) * 1000000) + t.tv_usec;
}

const char * test_n_hex = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496"
   "EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8E"
   "F4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA"
   "9AFD5138FE8376435B9FC61D2FC0EB06E3";
const char * test_g_hex = "2";



/* PKCS #11 setup and session opening
 */
CK_RV pkcs11_setup (CK_SESSION_HANDLE *sesp) {
	CK_SLOT_ID slots [100];
	CK_ULONG num_slots = 100;
	CK_BYTE_PTR pin;
	CK_RV ckrv;
	ckrv = C_Initialize (NULL_PTR);
	if (ckrv != CKR_OK) return ckrv;
	ckrv = C_GetSlotList (CK_TRUE, slots, &num_slots);
	if (ckrv != CKR_OK) return ckrv;
	if (num_slots < 1) {
		fprintf (stderr, "Failed to find the first token\n");
		*sesp = CK_INVALID_HANDLE;
		return CKR_TOKEN_NOT_RECOGNIZED;
	}
	ckrv = C_OpenSession (slots [0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, sesp);
	if (ckrv != CKR_OK) return ckrv;
	pin = getpass ("Token PIN: ");
	if ((!pin) || (!*pin)) {
		fprintf (stderr, "Bailing out without login attempt\n");
		return CKR_USER_NOT_LOGGED_IN;
	}
	ckrv = C_Login (*sesp, CKU_USER, pin, strlen (pin));
	bzero (pin, strlen (pin));
	return ckrv;
}


void pkcs11_cleanup (CK_SESSION_HANDLE ses) {
	CK_RV ckrv;
	ckrv = C_CloseSession (ses);
	if (ckrv != CKR_OK) {
		fprintf (stderr, "Failed to close PKCS #11 session: 0x%08x\n", ckrv);
		return;
	}
	ckrv = C_Finalize (NULL_PTR);
	if (ckrv != CKR_OK) {
		fprintf (stderr, "Failed to finalise PKCS #11 library: 0x%08x\n", ckrv);
		return;
	}
}


int main( int argc, char * argv[] )
{
    struct SRPVerifier * ver;
    struct SRP11User   * usr;
    
    unsigned char * bytes_pubkey = 0;
    unsigned char * bytes_pubkey2 = 0;
    unsigned char * bytes_s = 0;
    unsigned char * bytes_v = 0;
    unsigned char * bytes_A = 0;
    unsigned char * bytes_B = 0;
    
    unsigned char * bytes_M    = 0;
    unsigned char * bytes_HAMK = 0;
    
    int len_pubkey = 0;
    int len_pubkey2 = 0;
    int len_s   = 0;
    int len_v   = 0;
    int len_A   = 0;
    int len_B   = 0;
    int len_M   = 0;
    int i;
    
    unsigned long long start;
    unsigned long long duration;
    
    const char * username = "testuser";
    
    const char * auth_username = 0;
    const char * n_hex         = 0;
    const char * g_hex         = 0;
    
    SRP_HashAlgorithm alg     = TEST_HASH;
    SRP_NGType        ng_type = SRP_NG_8192; //TEST_NG;

    CK_RV ckrv;
    CK_SESSION_HANDLE p11ses;
    CK_OBJECT_HANDLE srp11pub, srp11priv, srp11pub2;
 
    if (ng_type == SRP_NG_CUSTOM)
    {
        n_hex = test_n_hex;
        g_hex = test_g_hex;
    }

    ckrv = pkcs11_setup (&p11ses);

    if (ckrv != CKR_OK) {
	printf ("Failed to open PKCS #11 session: 0x%08x\n", ckrv);
	goto cleanup11;
    }

    /* Create a new key over PKCS #11, but supply no additional CKA_xxx
     * attributes, so the key will automatically be a session key, which is
     * sufficient for testing purposes.
     *
     * For token-stored keys, you would add CKA_TOKEN set to CK_TRUE and
     * then you should also define a way to store the username, perhaps in
     * CKA_ID and/or CKA_LABEL.  The SRP #11 library routines do not deal
     * with usernames at all, that is up to an application's interaction
     * with PKCS #11.
     */
    ckrv = srp11_create_new_keys ( p11ses, NULL, 0,
			ng_type, n_hex, g_hex,
			&srp11pub, &srp11priv);

    if (ckrv != CKR_OK) {
	printf ("Failed to create a new key: 0x%08x\n", ckrv);
	goto cleanup11;
    }

    ckrv = srp11_retrieve_pubkey (p11ses, srp11pub, &bytes_pubkey, &len_pubkey);

    if (ckrv != CKR_OK) {
	printf ("Failed to retrieve public key: 0x%08x\n", ckrv);
	goto cleanup11;
    }

    ckrv = srp11_regenerate_pubkey (p11ses, srp11priv, NULL, 0, &srp11pub2);

    if (ckrv != CKR_OK) {
	printf ("Failed to regenerate the public key: 0x%08x\n", ckrv);
	goto cleanup11;
    }

    ckrv = srp11_retrieve_pubkey (p11ses, srp11pub2, &bytes_pubkey2, &len_pubkey2);

    if (ckrv != CKR_OK) {
	printf ("Failed to retrieve regenerated public key: 0x%08x\n", ckrv);
	goto cleanup11;
    }

    if ((len_pubkey != len_pubkey2) || memcmp (bytes_pubkey, bytes_pubkey2, len_pubkey)) {
	printf ("Directly and indirectly retrieved public keys differ?!?\n");
	goto cleanup;
    }

    /* Based on the SRP #11 key's object handle, TODO */
    ckrv = srp11_create_salted_verification_key (
		p11ses, srp11priv, bytes_pubkey, len_pubkey,
		alg,
                &bytes_s, &len_s, &bytes_v, &len_v);
    
    if (ckrv != CKR_OK) {
	printf ("Failed to create salt `n' verifier: 0x%08x\n", ckrv);
	goto cleanup11;
    }

    
    start = get_usec();
    
    for( i = 0; i < NITER; i++ )
    {
	/* Create a new user instance
	 */
        ckrv =  srp11_user_new (
		p11ses, srp11priv,
		alg,
		bytes_pubkey, len_pubkey,
		(char *) username,
		&usr);

	if (ckrv != CKR_OK) {
	    printf ("Failed to start new user session: 0x%08x\n", ckrv);
	    goto cleanup;
	}

	/* Start authentication on the client, by computing A
	 */
        srp11_user_start_authentication (usr, &bytes_A, &len_A);

        /* User -> Host: (username), bytes_A/len/A
	 */
        ver =  srp_verifier_new( alg, ng_type, username, bytes_s, len_s, bytes_v, len_v, 
                                 (const unsigned char *) bytes_A, len_A, (const unsigned char **) & bytes_B, &len_B, n_hex, g_hex, 1 );
        
        if ((bytes_B == NULL) || (len_B <= 0)) {
		printf("Verifier SRP-6a safety check violated!\n");
		goto cleanup;
        }

        /* Host -> User: bytes_s/len_s, bytes_B/len_B
	 * User -> Host: bytes_M/len_M
	 */
        ckrv = srp11_user_process_challenge (usr, bytes_s, len_s, bytes_B, len_B, &bytes_M, &len_M);

	if (ckrv != CKR_OK) {
		printf ("Failed to process challenge on user end: 0x%08x\n", ckrv);
		goto cleanup;
	}

        if ((bytes_M == NULL) || (len_M <= 0)) {
		printf("User SRP-6a safety check violation!\n");
		goto cleanup;
	}

        /* User -> Host: (bytes_M) */
        srp_verifier_verify_session (ver, (const unsigned char *) bytes_M, (const unsigned char **) &bytes_HAMK);
        
        if ( !bytes_HAMK )
        {
            printf("Failed to verify the user on the service side!\n");
            goto cleanup;
        }

        /* Host -> User: (HAMK) */
        ckrv = srp11_user_verify_session (usr, bytes_HAMK);

	if (ckrv != CKR_OK) {
	    printf ("Failed to verify the session on the user end: 0x%08x\n", ckrv);
	    goto cleanup;
	}

	if (!srp11_user_has_authenticated_service (usr)) {
		printf("Server authentication failed!\n");
	}
        
cleanup:
        srp_verifier_delete( ver );
        srp11_user_delete( usr );
    }
    
    duration = get_usec() - start;
    
    printf("Usec per call: %d\n", (int)(duration / NITER));
    
    
    free( (char *)bytes_s );
    free( (char *)bytes_v );

cleanup11:
    if (p11ses != CK_INVALID_HANDLE) {
	pkcs11_cleanup (p11ses);
    }
        
    return 0;
}
