#!/usr/bin/env sh

# test enc
# doesn't work with EVP_CIPH_FLAG_AEAD_CIPHER

ENC="apps/openssl enc -caesar"
PLAINTEXT="Lorem ipsum dolor sit amet, consectetur adipiscing elit."
# KEY=123456789abcdef03456789abcdef012
# IV=00000000000000000000000000000000
KEY=$(openssl rand 16 | xxd -p)
IV=$(openssl rand 16 | xxd -p)


echo "$PLAINTEXT"
echo "key=$KEY"
echo "iv=$IV"
echo
CIPHERTEXT=$(echo -n "$PLAINTEXT" | $ENC -K $KEY -iv $IV | xxd -p)
echo
echo "$CIPHERTEXT"
echo
PLAINTEXT2=$(echo -n "$CIPHERTEXT" | xxd -r -p | $ENC -d -K $KEY -iv $IV)
echo
echo "$PLAINTEXT2"
echo


if [ "$PLAINTEXT" == "$PLAINTEXT2" ]; then
  echo "ok"
else
  echo "fail"
fi
