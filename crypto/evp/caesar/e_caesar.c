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
    const unsigned char *in, size_t inl); // encrypt/decrypt cipher_ctx
  int (*cleanup)(EVP_CIPHER_CTX *); // cleanup ctx
  int ctx_size; // how big ctx->cipher_data needs to be
  int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *); // Populate a ASN1_TYPE with parameters
  int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *); // Get parameters from a ASN1_TYPE
  int (*ctrl)(EVP_CIPHER_CTX *, int type, int arg, void *ptr); // Miscellaneous operations
  void *app_data; // Application cipher_ctx
} EVP_CIPHER;
*/



#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 12
#define CRYPTO_ABYTES 16

#define CRYPTO_DEBUG 1

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k);

typedef struct {
  const unsigned char *key;
  unsigned char *nsec;
  unsigned char *npub;
  unsigned char *ad;
  size_t ad_length;
} EVP_CAESAR_CTX;

static int caesar_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
static int caesar_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
static int caesar_cleanup(EVP_CIPHER_CTX *ctx);
static int caesar_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static const EVP_CIPHER caesar = {
  NID_caesar,
  1,
  CRYPTO_KEYBYTES,
  0,
  EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER,
  caesar_init_key,
  caesar_cipher,
  caesar_cleanup,
  sizeof(EVP_CAESAR_CTX),
  NULL,
  NULL,
  caesar_ctrl,
  NULL
};

const EVP_CIPHER *EVP_caesar(void) {
  return &caesar;
}

static int caesar_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc) {
#ifdef CRYPTO_DEBUG
  fprintf(stderr, "caesar_init_key\n");
#endif

  EVP_CAESAR_CTX *cipher_ctx = (EVP_CAESAR_CTX *)ctx->cipher_data;

  cipher_ctx->key = key;
  cipher_ctx->nsec = (unsigned char *)calloc(CRYPTO_NSECBYTES, sizeof(unsigned char));
  cipher_ctx->npub = (unsigned char *)calloc(CRYPTO_NPUBBYTES, sizeof(unsigned char));
  cipher_ctx->ad = (unsigned char *)calloc(1, sizeof(unsigned char));
  cipher_ctx->ad_length = 0;

  return 1;
}

static int caesar_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t in_length) {
#ifdef CRYPTO_DEBUG
  fprintf(stderr, "caesar_cipher: in_length=%d\n", (int)in_length);
#endif

  int ret = 0;
  int out_length = 0;
  EVP_CAESAR_CTX *cipher_ctx = (EVP_CAESAR_CTX *)ctx->cipher_data;

  if (in == out) {
    // speed benchmark doesn't work
    return -1;
  }


  if (in_length > 0) {
    if (out == NULL) {
      // associated data
      free(cipher_ctx->ad);
      cipher_ctx->ad = (unsigned char *)calloc(in_length, sizeof(unsigned char));
      cipher_ctx->ad_length = in_length;
      memcpy(cipher_ctx->ad, in, in_length);
    } else {
      // message
      if (ctx->encrypt) {
        ret = crypto_aead_encrypt(out, &out_length, in, in_length, cipher_ctx->ad, cipher_ctx->ad_length, cipher_ctx->nsec, cipher_ctx->npub, cipher_ctx->key);
      } else {
        ret = crypto_aead_decrypt(out, &out_length, cipher_ctx->nsec, in, in_length, cipher_ctx->ad, cipher_ctx->ad_length, cipher_ctx->npub, cipher_ctx->key);
      }
    }
  }


#ifdef CRYPTO_DEBUG
  fprintf(stderr, "  out_length=%d ret=%d\n", out_length, ret);
#endif

  return ret == 0 ? out_length : ret;
}

static int caesar_cleanup(EVP_CIPHER_CTX *ctx) {
#ifdef CRYPTO_DEBUG
  fprintf(stderr, "caesar_cleanup\n");
#endif

  EVP_CAESAR_CTX *cipher_ctx = (EVP_CAESAR_CTX *)ctx->cipher_data;

  free(cipher_ctx->nsec);
  free(cipher_ctx->npub);
  free(cipher_ctx->ad);

  return 1;
}

static int caesar_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
#ifdef CRYPTO_DEBUG
  fprintf(stderr, "caesar_ctrl: type=%d arg=%d\n", type, arg);
#endif

  return 1;
}
