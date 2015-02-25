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

int fprintf_hex(FILE *stream, const unsigned char *in, size_t in_length) {
  size_t i;

  for (i = 0; i < in_length; i++) {
    fprintf(stream, "%02x", in[i]);
  }
}

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k);

typedef struct {
  const unsigned char *key;
  unsigned char *nsec;
  unsigned char *npub;
  unsigned char *ad;
  size_t ad_length;
  int is_tls;
} EVP_CAESAR_CTX;

static int caesar_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
static int caesar_set_ad(EVP_CIPHER_CTX *ctx, const unsigned char *in, size_t in_length);
static int caesar_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);
static int caesar_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k);
static int caesar_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t in_length);
static int caesar_cleanup(EVP_CIPHER_CTX *ctx);
static int caesar_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static const EVP_CIPHER caesar = {
  NID_caesar,
  1,
  CRYPTO_KEYBYTES,
  0,
  EVP_CIPH_CUSTOM_IV | EVP_CIPH_CTRL_INIT | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER,
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

static int caesar_init(EVP_CIPHER_CTX *ctx) {
#ifdef CRYPTO_DEBUG
  fprintf(stderr, "  caesar_init\n");
#endif

  EVP_CAESAR_CTX *cipher_ctx = (EVP_CAESAR_CTX *)ctx->cipher_data;

  cipher_ctx->nsec = (unsigned char *)calloc(CRYPTO_NSECBYTES, sizeof(unsigned char));
  cipher_ctx->npub = (unsigned char *)calloc(CRYPTO_NPUBBYTES, sizeof(unsigned char));
  cipher_ctx->ad = (unsigned char *)calloc(1, sizeof(unsigned char));
  cipher_ctx->ad_length = 0;
  cipher_ctx->is_tls = 0;

  return 1;
}

static int caesar_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc) {
#ifdef CRYPTO_DEBUG
  fprintf(stderr, "caesar_init_key\n");
#endif

  EVP_CAESAR_CTX *cipher_ctx = (EVP_CAESAR_CTX *)ctx->cipher_data;

  cipher_ctx->key = (unsigned char *)calloc(CRYPTO_KEYBYTES, sizeof(unsigned char));
  memcpy(cipher_ctx->key, key, CRYPTO_KEYBYTES);

  return 1;
}

static int caesar_set_ad(EVP_CIPHER_CTX *ctx, const unsigned char *in, size_t in_length) {
#ifdef CRYPTO_DEBUG
  fprintf(stderr, "  caesar_set_ad:\n");
  fprintf(stderr, "    in_length=%d\n", (int)in_length);
  fprintf(stderr, "    in=");
  fprintf_hex(stderr, in, in_length);
  fprintf(stderr, "\n");
#endif

  EVP_CAESAR_CTX *cipher_ctx = (EVP_CAESAR_CTX *)ctx->cipher_data;

  if (cipher_ctx->ad) {
    free(cipher_ctx->ad);
  }

  cipher_ctx->ad = (unsigned char *)calloc(in_length, sizeof(unsigned char));
  cipher_ctx->ad_length = in_length;
  memcpy(cipher_ctx->ad, in, in_length);

  return 1;
}

static int caesar_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) {
#ifdef CRYPTO_DEBUG
  fprintf(stderr, "  caesar_encrypt:\n");
  fprintf(stderr, "    mlen=%d\n", (int)mlen);
  fprintf(stderr, "    m=");
  fprintf_hex(stderr, m, mlen);
  fprintf(stderr, "\n");
  fprintf(stderr, "    adlen=%d\n", (int)adlen);
  fprintf(stderr, "    ad=");
  fprintf_hex(stderr, ad, adlen);
  fprintf(stderr, "\n");
  fprintf(stderr, "    k=");
  fprintf_hex(stderr, k, CRYPTO_KEYBYTES);
  fprintf(stderr, "\n");
#endif

  int ret = crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);

#ifdef CRYPTO_DEBUG
  fprintf(stderr, "    clen=%d\n", (int)*clen);
  fprintf(stderr, "    c=");
  fprintf_hex(stderr, c, (int)*clen);
  fprintf(stderr, "\n");
  fprintf(stderr, "    ret=%d\n", ret);
#endif

  return ret;
}

int caesar_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k) {
  #ifdef CRYPTO_DEBUG
    fprintf(stderr, "  caesar_decrypt:\n");
    fprintf(stderr, "    clen=%d\n", (int)clen);
    fprintf(stderr, "    c=");
    fprintf_hex(stderr, c, clen);
    fprintf(stderr, "\n");
    fprintf(stderr, "    adlen=%d\n", (int)adlen);
    fprintf(stderr, "    ad=");
    fprintf_hex(stderr, ad, adlen);
    fprintf(stderr, "\n");
    fprintf(stderr, "    k=");
    fprintf_hex(stderr, k, CRYPTO_KEYBYTES);
    fprintf(stderr, "\n");
  #endif

  int ret = crypto_aead_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k);

#ifdef CRYPTO_DEBUG
  fprintf(stderr, "  mlen=%d\n", (int)*mlen);
  fprintf(stderr, "  m=");
  fprintf_hex(stderr, m, (int)*mlen);
  fprintf(stderr, "\n");
  fprintf(stderr, "  ret=%d\n", ret);
#endif

  return ret;
}

static int caesar_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t in_length) {
#ifdef CRYPTO_DEBUG
  fprintf(stderr, "caesar_cipher:\n");
  fprintf(stderr, "  in_length=%d\n", (int)in_length);
  fprintf(stderr, "  in=");
  fprintf_hex(stderr, in, in_length);
  fprintf(stderr, "\n");
#endif

  int ret = 0;
  int out_length = 0;
  EVP_CAESAR_CTX *cipher_ctx = (EVP_CAESAR_CTX *)ctx->cipher_data;

  if (in_length > 0) {
    if (out == NULL) {
      caesar_set_ad(ctx, in, in_length);
    } else {
      // correct length for AEAD tag
      if (cipher_ctx->is_tls && ctx->encrypt) {
        in_length -= CRYPTO_ABYTES;
      }

      // duplicate input, because EVP can call encrypt with input and output with the same reference
      unsigned char *in_dup = (unsigned char *)calloc(in_length, sizeof(unsigned char));
      memcpy(in_dup, in, in_length);

      // message
      if (ctx->encrypt) {
        ret = caesar_encrypt(out, &out_length, in_dup, in_length, cipher_ctx->ad, cipher_ctx->ad_length, cipher_ctx->nsec, cipher_ctx->npub, cipher_ctx->key);
      } else {
        ret = caesar_decrypt(out, &out_length, cipher_ctx->nsec, in_dup, in_length, cipher_ctx->ad, cipher_ctx->ad_length, cipher_ctx->npub, cipher_ctx->key);
      }
    }
  }


#ifdef CRYPTO_DEBUG
  fprintf(stderr, "  out_length=%d\n", (int)out_length);
  fprintf(stderr, "  out=");
  fprintf_hex(stderr, out, out_length);
  fprintf(stderr, "\n");
  fprintf(stderr, "  ret=%d\n", ret);
#endif

  return ret == 0 ? out_length : ret;
}

static int caesar_cleanup(EVP_CIPHER_CTX *ctx) {
#ifdef CRYPTO_DEBUG
  fprintf(stderr, "caesar_cleanup\n");
#endif

  EVP_CAESAR_CTX *cipher_ctx = (EVP_CAESAR_CTX *)ctx->cipher_data;

  free(cipher_ctx->key);
  free(cipher_ctx->nsec);
  free(cipher_ctx->npub);
  free(cipher_ctx->ad);

  return 1;
}

static int caesar_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
#ifdef CRYPTO_DEBUG
  fprintf(stderr, "caesar_ctrl:\n");
  fprintf(stderr, "  type=%d\n", type);
  fprintf(stderr, "  arg=%d\n", arg);
  fprintf(stderr, "  ptr=");
  fprintf_hex(stderr, ptr, arg);
  fprintf(stderr, "\n");
#endif

  EVP_CAESAR_CTX *cipher_ctx = (EVP_CAESAR_CTX *)ctx->cipher_data;

  switch (type) {
    case EVP_CTRL_INIT:
      caesar_init(ctx);
      return 1;
    case EVP_CTRL_AEAD_TLS1_AAD: ; // empty statement
      int in_length = arg;
      unsigned char *in = (unsigned char *)ptr;

      cipher_ctx->is_tls = 1;

      if (!ctx->encrypt) {
        // correct length for AEAD tag
        // @see e_aes.c
        unsigned int len = in[in_length - 2] << 8 | in[in_length - 1];
        len -= CRYPTO_ABYTES;

        in[in_length - 2] = len >> 8;
        in[in_length - 1] = len & 0xff;
      }

      caesar_set_ad(ctx, in, in_length);
      return CRYPTO_ABYTES; // AEAD tag length
    default:
      return -1;
  }
}
