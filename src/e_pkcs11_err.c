/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "e_pkcs11_err.h"

#ifndef OPENSSL_NO_ERR

static ERR_STRING_DATA PKCS11_str_functs[] = {
    {ERR_PACK(0, PKCS11_F_BIND_PKCS11, 0), "bind_pkcs11"},
    {ERR_PACK(0, PKCS11_F_PKCS11_CTRL, 0), "pkcs11_ctrl"},
    {ERR_PACK(0, PKCS11_F_PKCS11_CTX_NEW, 0), "pkcs11_ctx_new"},
    {ERR_PACK(0, PKCS11_F_PKCS11_ENGINE_LOAD_PRIVATE_KEY, 0),
     "pkcs11_engine_load_private_key"},
    {ERR_PACK(0, PKCS11_F_PKCS11_FIND_PRIVATE_KEY, 0),
     "pkcs11_find_private_key"},
    {ERR_PACK(0, PKCS11_F_PKCS11_FIND_PUBLIC_KEY, 0), "pkcs11_find_public_key"},
    {ERR_PACK(0, PKCS11_F_PKCS11_GET_CONSOLE_PIN, 0), "pkcs11_get_console_pin"},
    {ERR_PACK(0, PKCS11_F_PKCS11_GET_SLOT, 0), "pkcs11_get_slot"},
    {ERR_PACK(0, PKCS11_F_PKCS11_INIT, 0), "pkcs11_init"},
    {ERR_PACK(0, PKCS11_F_PKCS11_INITIALIZE, 0), "pkcs11_initialize"},
    {ERR_PACK(0, PKCS11_F_PKCS11_LOAD_FUNCTIONS, 0), "pkcs11_load_functions"},
    {ERR_PACK(0, PKCS11_F_PKCS11_LOAD_PKEY, 0), "pkcs11_load_pkey"},
    {ERR_PACK(0, PKCS11_F_PKCS11_LOGIN, 0), "pkcs11_login"},
    {ERR_PACK(0, PKCS11_F_PKCS11_LOGOUT, 0), "pkcs11_logout"},
    {ERR_PACK(0, PKCS11_F_PKCS11_PARSE, 0), "pkcs11_parse"},
    {ERR_PACK(0, PKCS11_F_PKCS11_PARSE_ITEMS, 0), "pkcs11_parse_items"},
    {ERR_PACK(0, PKCS11_F_PKCS11_RSA_ENC, 0), "pkcs11_rsa_enc"},
    {ERR_PACK(0, PKCS11_F_PKCS11_RSA_INIT, 0), "pkcs11_rsa_init"},
    {ERR_PACK(0, PKCS11_F_PKCS11_RSA_PRIV_DEC, 0), "pkcs11_rsa_priv_dec"},
    {ERR_PACK(0, PKCS11_F_PKCS11_RSA_PRIV_ENC, 0), "pkcs11_rsa_priv_enc"},
    {ERR_PACK(0, PKCS11_F_PKCS11_RSA_SIGN, 0), "pkcs11_rsa_sign"},
    {ERR_PACK(0, PKCS11_F_PKCS11_START_SESSION, 0), "pkcs11_start_session"},
    {ERR_PACK(0, PKCS11_F_PKCS11_TRACE, 0), "PKCS11_trace"},
    {0, NULL}
};

static ERR_STRING_DATA PKCS11_str_reasons[] = {
    {ERR_PACK(0, 0, PKCS11_R_DECRYPT_FAILED), "encrypt failed"},
    {ERR_PACK(0, 0, PKCS11_R_DECRYPT_INIT_FAILED), "encrypt init failed"},
    {ERR_PACK(0, 0, PKCS11_R_DIGEST_TOO_BIG_FOR_RSA_KEY),
    "digest too big for rsa key"},
    {ERR_PACK(0, 0, PKCS11_R_ENCRYPT_FAILED), "encrypt failed"},
    {ERR_PACK(0, 0, PKCS11_R_ENCRYPT_INIT_FAILED), "encrypt init failed"},
    {ERR_PACK(0, 0, PKCS11_R_ENGINE_NOT_INITIALIZED), "engine not initialized"},
    {ERR_PACK(0, 0, PKCS11_R_FILE_OPEN_ERROR), "file open error"},
    {ERR_PACK(0, 0, PKCS11_R_FIND_OBJECT_FAILED), "find object failed"},
    {ERR_PACK(0, 0, PKCS11_R_FIND_OBJECT_FINAL_FAILED),
    "find object final failed"},
    {ERR_PACK(0, 0, PKCS11_R_FIND_OBJECT_INIT_FAILED),
    "find object init failed"},
    {ERR_PACK(0, 0, PKCS11_R_GETATTRIBUTEVALUE_FAILED),
    "getattributevalue failed"},
    {ERR_PACK(0, 0, PKCS11_R_GETFUNCTIONLIST_NOT_FOUND),
    "getfunctionlist not found"},
    {ERR_PACK(0, 0, PKCS11_R_GETTING_FUNCTION_LIST_FAILED),
    "getting function list failed"},
    {ERR_PACK(0, 0, PKCS11_R_GET_SLOTINFO_FAILED), "get slotinfo failed"},
    {ERR_PACK(0, 0, PKCS11_R_GET_SLOTLIST_FAILED), "get slotlist failed"},
    {ERR_PACK(0, 0, PKCS11_R_INITIALIZE_FAILED), "initialize failed"},
    {ERR_PACK(0, 0, PKCS11_R_LIBRARY_PATH_NOT_FOUND), "library path not found"},
    {ERR_PACK(0, 0, PKCS11_R_LOGIN_FAILED), "login failed"},
    {ERR_PACK(0, 0, PKCS11_R_LOGOUT_FAILED), "logout failed"},
    {ERR_PACK(0, 0, PKCS11_R_MEMORY_ALLOCATION_FAILED),
    "memory allocation failed"},
    {ERR_PACK(0, 0, PKCS11_R_OPEN_SESSION_ERROR), "open session error"},
    {ERR_PACK(0, 0, PKCS11_R_PADDING_ADD_FAILED), "padding add failed"},
    {ERR_PACK(0, 0, PKCS11_R_RSA_INIT_FAILED), "rsa init failed"},
    {ERR_PACK(0, 0, PKCS11_R_RSA_NOT_FOUND), "rsa not found"},
    {ERR_PACK(0, 0, PKCS11_R_SIGN_FAILED), "sign failed"},
    {ERR_PACK(0, 0, PKCS11_R_SIGN_INIT_FAILED), "sign init failed"},
    {ERR_PACK(0, 0, PKCS11_R_SLOT_NOT_FOUND), "slot not found"},
    {ERR_PACK(0, 0, PKCS11_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD),
    "the asn1 object identifier is not known for this md"},
    {ERR_PACK(0, 0, PKCS11_R_UNKNOWN_ALGORITHM_TYPE), "unknown algorithm type"},
    {ERR_PACK(0, 0, PKCS11_R_VERIFY_FAILED), "sign failed"},
    {ERR_PACK(0, 0, PKCS11_R_VERIFY_INIT_FAILED), "sign init failed"},
    {0, NULL}
};

#endif

static int lib_code = 0;
static int error_loaded = 0;

static int ERR_load_PKCS11_strings(void)
{
    if (lib_code == 0)
        lib_code = ERR_get_next_error_library();

    if (!error_loaded) {
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(lib_code, PKCS11_str_functs);
        ERR_load_strings(lib_code, PKCS11_str_reasons);
#endif
        error_loaded = 1;
    }
    return 1;
}

static void ERR_unload_PKCS11_strings(void)
{
    if (error_loaded) {
#ifndef OPENSSL_NO_ERR
        ERR_unload_strings(lib_code, PKCS11_str_functs);
        ERR_unload_strings(lib_code, PKCS11_str_reasons);
#endif
        error_loaded = 0;
    }
}
