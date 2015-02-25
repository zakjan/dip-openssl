#!/usr/bin/env sh

# test enc
# doesn't work with EVP_CIPH_FLAG_AEAD_CIPHER

OPENSSL_DIR=apps
PLAINTEXT="Lorem ipsum dolor sit amet, consectetur adipiscing elit."
KEY=$(openssl rand 16 | xxd -p)


echo "$PLAINTEXT"
echo
CIPHERTEXT=$(echo -n "$PLAINTEXT" | $OPENSSL_DIR/openssl enc -caesar -K $KEY | xxd -p)
echo
echo "$CIPHERTEXT"
echo
PLAINTEXT2=$(echo -n "$CIPHERTEXT" | xxd -r -p | $OPENSSL_DIR/openssl enc -d -caesar -K $KEY)
echo
echo "$PLAINTEXT2"
echo


if [ "$PLAINTEXT" == "$PLAINTEXT2" ]; then
  echo "ok"
else
  echo "fail"
fi
