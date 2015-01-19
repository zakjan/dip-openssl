#include <openssl/evp.h>

// from crypto/evp/evp.h
/*
struct evp_cipher_st {
  int nid;
  int block_size;
  int key_len; // Default value for variable length ciphers
  int iv_len;
  unsigned long flags; // Various flags
  int (*init)(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc); // init key
  int (*do_cipher)(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t inl); // encrypt/decrypt data
  int (*cleanup)(EVP_CIPHER_CTX *); // cleanup ctx
  int ctx_size; // how big ctx->cipher_data needs to be
  int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *); // Populate a ASN1_TYPE with parameters
  int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *); // Get parameters from a ASN1_TYPE
  int (*ctrl)(EVP_CIPHER_CTX *, int type, int arg, void *ptr); // Miscellaneous operations
  void *app_data; // Application data
} EVP_CIPHER;
*/

static int caesar_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
static int caesar_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
static int caesar_cleanup(EVP_CIPHER_CTX *ctx);
static int caesar_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static const EVP_CIPHER caesar = {
  NID_caesar,
  1,
  16,
  16,
  EVP_CIPH_FLAG_CUSTOM_CIPHER,
  caesar_init_key,
  caesar_cipher,
  caesar_cleanup,
  0,
  NULL,
  NULL,
  caesar_ctrl,
  NULL
};

const EVP_CIPHER *EVP_caesar(void) {
  return &caesar;
}

static int caesar_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc) {
  return 1;
}

static int caesar_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t in_length) {
  size_t i;
  int out_length = -1;

  if (in == out) {
    return;
  }

  if (ctx->encrypt) {
    for (i = 0; i < in_length; i++) {
      out[i] = in[i] + 13;
    }
    out_length = in_length;
  } else {
    for (i = 0; i < in_length; i++) {
      out[i] = in[i] - 13;
    }
    out_length = in_length;
  }

  return out_length;
}

static int caesar_cleanup(EVP_CIPHER_CTX *ctx) {
  return 1;
}

static int caesar_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
  return 1;
}
