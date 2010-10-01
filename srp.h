/*
 * Secure Remote Password 6a implementation
 * Copyright (c) 2010 Tom Cocagne. All rights reserved.
 * http://csrp.googlecode.com/p/csrp/
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Google Code nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL TOM COCAGNE BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF 
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */

/* 
 * 
 * Purpose:       This is a direct implementation of the Secure Remote Password
 *                Protocol version 6a as described by 
 *                http://srp.stanford.edu/design.html
 * 
 * Author:        tom.cocagne@gmail.com (Tom Cocagne)
 * 
 * Dependencies:  OpenSSL (and Advapi32.lib on Windows)
 * 
 * Usage:         Refer to test_srp.c for a demonstration
 * 
 * Note: 
 *    The SRP protocol does not mandate a specific hashing algorithm. This
 *    implementation uses SHA256 rather than SHA1 for additional security
 *    and the increased number of bytes in the resulting shared key. However,
 *    SHA256 is approximately 20% slower than SHA1. If speed is more important
 *    than the key length and/or added security, you may change it to SHA1.
 * 
 */

#ifndef SRP_H
#define SRP_H

#define SRP_SHA256_DIGEST_LENGTH 32

/* srp_init() must be called prior to usage of any other srp_* functions.
 * and a matching srp_fini() will clean up all memory allocated by srp_init().
 */
void srp_init();
void srp_fini();

/* Returns 1 if srp_init() if the library is initialized */
int  srp_is_initialized(); 


struct SRPVerifier;
struct SRPUser;


/* Out: bytes_s, len_s, bytes_v, len_v
 * 
 * The caller is responsible for freeing the memory allocated for bytes_s and bytes_v
 */
void srp_gen_sv( const char * username,
                 const unsigned char * password, int len_password,
                 const unsigned char ** bytes_s, int * len_s, 
                 const unsigned char ** bytes_v, int * len_v );


/* Out: bytes_B, len_B.
 * 
 * On failure, bytes_B will be set to NULL and len_B will be set to 0
 */
struct SRPVerifier *  srp_verifier_new( const char * username,
                                        const unsigned char * bytes_s, int len_s, 
                                        const unsigned char * bytes_v, int len_v,
                                        const unsigned char * bytes_A, int len_A,
                                        const unsigned char ** bytes_B, int * len_B);


void                  srp_verifier_delete( struct SRPVerifier * ver );


int                   srp_verifier_is_authenticated( struct SRPVerifier * ver );


const char *          srp_verifier_get_username( struct SRPVerifier * ver );


/* Key length is SRP_SHA256_DIGEST_LENGTH */
const unsigned char * srp_verifier_get_session_key( struct SRPVerifier * ver );


/* user_M must be exactly SRP_SHA256_DIGEST_LENGTH bytes in size */
void                  srp_verifier_verify_session( struct SRPVerifier * ver,
                                                   const unsigned char * user_M, 
                                                   const unsigned char ** bytes_HAMK );

/*******************************************************************************/

struct SRPUser *      srp_user_new( const char * username, 
                                    const unsigned char * bytes_password, int len_password );
                                    
void                  srp_user_delete( struct SRPUser * usr );

int                   srp_user_is_authenticated( struct SRPUser * usr);


const char *          srp_user_get_username( struct SRPUser * usr );

/* Key length is SRP_SHA256_DIGEST_LENGTH */
const unsigned char * srp_user_get_session_key( struct SRPUser * usr );

/* Output: username, bytes_A, len_A */
void                  srp_user_start_authentication( struct SRPUser * usr, const char ** username, 
                                                     const unsigned char ** bytes_A, int * len_A );

/* Output: bytes_M. Buffer length is SRP_SHA256_DIGEST_LENGTH */
void                  srp_user_process_challenge( struct SRPUser * usr, 
                                                  const unsigned char * bytes_s, int len_s, 
                                                  const unsigned char * bytes_B, int len_B,
                                                  const unsigned char ** bytes_M );
                                                  
/* bytes_HAMK must be exactly SRP_SHA256_DIGEST_LENGTH bytes in size */
void                  srp_user_verify_session( struct SRPUser * usr, const unsigned char * bytes_HAMK );

#endif /* Include Guard */