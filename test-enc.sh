#!/usr/bin/env sh

PLAINTEXT="Lorem ipsum dolor sit amet, consectetur adipiscing elit."


echo "$PLAINTEXT"
echo
CIPHERTEXT=$(echo -n "$PLAINTEXT" | apps/openssl enc -caesar -pass pass:aaa -nosalt)
echo
echo "$CIPHERTEXT"
echo -n "$CIPHERTEXT" | xxd -p
echo
PLAINTEXT2=$(echo -n "$CIPHERTEXT" | apps/openssl enc -d -caesar -pass pass:aaa -nosalt)
echo
echo "$PLAINTEXT2"
echo


if [ "$PLAINTEXT" == "$PLAINTEXT2" ]; then
  echo "ok"
else
  echo "fail"
fi
