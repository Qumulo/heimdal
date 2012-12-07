/*
 * Copyright (c) 2006 - 2009 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $Id$ */

#ifndef GSSAPI_NTLM_H_
#define GSSAPI_NTLM_H_

#include <gssapi.h>
#include <heimntlm.h>

/* Allow users to override the ntlm server interface used in gssapi */

typedef OM_uint32
(*ntlm_interface_init)(OM_uint32 * /* minor */, void ** /* ctx */);

typedef OM_uint32
(*ntlm_interface_destroy)(OM_uint32 * /* minor */, void * /* ctx */);

typedef int
(*ntlm_interface_probe)(OM_uint32 * /* minor */, void * /* ctx */,
                        const char * /* realm_always_null */);

typedef OM_uint32
(*ntlm_interface_type2)(OM_uint32 * /* minor */, void * /* ctx */,
                        uint32_t /* flags */, const char * /* hostname */,
                        const char * /* domain */, uint32_t * /* ret_flags */,
                        struct ntlm_buf * /* encoded_ntlm_type2 */);

typedef OM_uint32
(*ntlm_interface_type3)(OM_uint32 * /* minor */, void * /* ctx */,
                        const struct ntlm_type3 * /* request */,
                        struct ntlm_buf * /* session_key */);

struct ntlm_server_interface {
    ntlm_interface_init nsi_init;
    ntlm_interface_destroy nsi_destroy;
    ntlm_interface_probe nsi_probe;
    ntlm_interface_type2 nsi_type2;
    ntlm_interface_type3 nsi_type3;
};

/*
 * Override the server interface.
 * This is not thread safe, do once before first gss_accept_sec_context()
 * The default is to use kdc_digest
 */
 
GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL gss_ntlm_set_server_interface(
            struct ntlm_server_interface *);

#endif /* GSSAPI_NTLM_H_ */
