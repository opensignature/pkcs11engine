/*
 * Copyright 2020 Antonio Iacono and the OpenSSL Project Authors.
 * All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/engine.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    X509 *signer = NULL;
    EVP_PKEY *key = NULL;
    CMS_ContentInfo *cms = NULL;
    OSSL_STORE_CTX *store_ctx = NULL;
    ENGINE *engine = NULL;
    const EVP_MD *sign_md = NULL;
    typedef struct pw_cb_data {
        const void *password;
        const char *prompt_info;
    } PW_CB_DATA;

    if (argc != 6) {
        fprintf(stderr, "Usage: signcms infile modpkcs11 id pin md\n");
        exit(1);
    }

    int ret = 1;
    char certuri[512];
    char privuri[512];

    int flags = CMS_CADES | CMS_STREAM | CMS_NOSMIMECAP |
                CMS_BINARY | CMS_PARTIAL;

    in = BIO_new_file(argv[1], "r");
    out = BIO_new_file("out.der", "wb");
    if (!in || !out)
        goto err;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if ((engine = ENGINE_by_id("pkcs11")) == NULL)
        goto err;

    if (!ENGINE_set_default(engine, -1))
        goto err;

    ENGINE_init(engine);

    sprintf(certuri,"pkcs11:type=cert;module-path=%s;id=%s",argv[2],argv[3]);
    char *uri = &certuri[0];
    if ((store_ctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL)) == NULL)
        goto err;

    OSSL_STORE_INFO *info = OSSL_STORE_load(store_ctx);
    if (!info)
        goto err;

    signer = OSSL_STORE_INFO_get0_CERT(info);

    if (!signer)
        goto err;

    cms = CMS_sign(NULL, NULL, NULL, in, flags);
    if (cms == NULL)
        goto err;

    CMS_SignerInfo *si;

    sprintf(privuri,"pkcs11:type=private;module-path=%s;id=%s;pin-value=%s",
            argv[2],argv[3],argv[4]);
    char *keyuri = &privuri[0];

    PW_CB_DATA cb_data;
    cb_data.password = NULL;
    cb_data.prompt_info = keyuri;
    key = ENGINE_load_private_key(engine, keyuri, NULL, &cb_data);

    if (key == NULL)
        goto err;

    sign_md = EVP_get_digestbyname(argv[5]);

    if (sign_md == NULL)
        goto err;

    si = CMS_add1_signer(cms, signer, key, sign_md, flags);

    if (si == NULL)
        goto err;

    if (!CMS_final(cms, in, NULL, flags))
        goto err;

    /* Write out ASN1 */
    if (!i2d_CMS_bio(out,cms))
        goto err;

    ret = 0;

 err:
    if (ret) {
        fprintf(stderr, "Error Signing Data\n");
        ERR_print_errors_fp(stderr);
    }

    ENGINE_finish(engine);
    ENGINE_free(engine);
    ENGINE_cleanup();
    CMS_ContentInfo_free(cms);
    X509_free(signer);
    EVP_PKEY_free(key);
    BIO_free(in);
    BIO_free(out);
    return ret;
}
