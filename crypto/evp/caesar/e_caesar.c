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



typedef struct {
  unsigned char *key;
  unsigned char *nsec;
  unsigned char *npub;
  unsigned char *ad;
} EVP_CAESAR_KEY;

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
  sizeof(EVP_CAESAR_KEY),
  NULL,
  NULL,
  caesar_ctrl,
  NULL
};

const EVP_CIPHER *EVP_caesar(void) {
  return &caesar;
}

#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 12
#define CRYPTO_ABYTES 16

#define CRYPTO_ADBYTES 16

static int caesar_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc) {
  fprintf(stderr, "caesar_init_key\n");

  EVP_CAESAR_KEY *data = (EVP_CAESAR_KEY *)ctx->cipher_data;

  data->key = (unsigned char *)calloc(CRYPTO_KEYBYTES, sizeof(unsigned char));
  data->nsec = (unsigned char *)calloc(CRYPTO_NSECBYTES, sizeof(unsigned char));
  data->npub = (unsigned char *)calloc(CRYPTO_NPUBBYTES, sizeof(unsigned char));
  data->ad = (unsigned char *)calloc(CRYPTO_ADBYTES, sizeof(unsigned char));

  memset(data->key, 0, CRYPTO_KEYBYTES);
  memset(data->nsec, 0, CRYPTO_NSECBYTES);
  memset(data->npub, 0, CRYPTO_NPUBBYTES);
  memset(data->ad, 0, CRYPTO_ADBYTES);

  return 1;
}

static int caesar_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t in_length) {
  fprintf(stderr, "caesar_cipher: in_length=%d\n", in_length);

  size_t i;
  int ret = 0;
  int out_length = 0;
  EVP_CAESAR_KEY *data = (EVP_CAESAR_KEY *)ctx->cipher_data;

  if (in == out) {
    return;
  }


  if (in_length > 0) {
    if (ctx->encrypt) {
      ret = crypto_aead_encrypt(out, &out_length, in, in_length, data->ad, CRYPTO_ADBYTES, data->nsec, data->npub, data->key);
    } else {
      ret = crypto_aead_decrypt(out, &out_length, data->nsec, in, in_length, data->ad, CRYPTO_ADBYTES, data->npub, data->key);
    }
  }


  return ret == 0 ? out_length : ret;
}

static int caesar_cleanup(EVP_CIPHER_CTX *ctx) {
  fprintf(stderr, "caesar_cleanup\n");

  EVP_CAESAR_KEY *data = (EVP_CAESAR_KEY *)ctx->cipher_data;

  free(data->key);
  free(data->nsec);
  free(data->npub);
  free(data->ad);

  return 1;
}

static int caesar_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
  return 1;
}
