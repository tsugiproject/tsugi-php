<?php

// Tsugi specific Aes encryption using OpenSSL Library
// https://stackoverflow.com/questions/3422759/php-aes-encrypt-decrypt

/* (From Stack Overflow)

    The following code:

    o   uses AES256 in CBC mode
    o   is compatible with other AES implementations, but not mcrypt, since mcrypt uses PKCS#5 instead of PKCS#7.
    o   generates a key from the provided password using SHA256
    o   generates a hmac hash of the encrypted data for integrity check
    o   generates a random IV for each message
    o   prepends the IV (16 bytes) and the hash (32 bytes) to the ciphertext
    o   should be pretty secure

 */

namespace Tsugi\Crypt;

class AesOpenSSL {

  /**
   * Unicode multi-byte character safe
   *
   * @param string $plaintext source text to be encrypted
   * @param string $password  the password to use to generate a key
   * @param int    $nBits     (ignored - always set to 256)
   * @return string   encrypted text
   */
  public static function encrypt($plaintext, $password, $nBits=256) {
    $method = "AES-256-CBC";
    if ( !is_string($plaintext) || ! is_string($password) ) return null;
    $key = hash('sha256', $password, true);
    $iv = openssl_random_pseudo_bytes(16);

    if ( ! is_string($plaintext) || ! is_string($password) ) return null;

    $ciphertext = openssl_encrypt($plaintext, $method, $key, OPENSSL_RAW_DATA, $iv);
    $hash = hash_hmac('sha256', $ciphertext . $iv, $key, true);

    $retval = base64_encode($iv . $hash . $ciphertext);
    return $retval;
  }

  /**
   * Decrypt a text encrypted by AES in counter mode of operation
   *
   * @param string $ciphertext source text to be decrypted
   * @param string $password   the password to use to generate a key
   * @param int    $nBits      (ignored - always set to 256)
   * @return string    decrypted text
   */
  public static function decrypt($ciphertext, $password, $nBits=256) {
    if ( ! is_string($ciphertext) || ! is_string($password) ) return null;

    $method = "AES-256-CBC";
    $ivHashCiphertext = base64_decode($ciphertext);
    $iv = substr($ivHashCiphertext, 0, 16);
    $hash = substr($ivHashCiphertext, 16, 32);
    $ciphertext = substr($ivHashCiphertext, 48);
    $key = hash('sha256', $password, true);

    if (!hash_equals(hash_hmac('sha256', $ciphertext . $iv, $key, true), $hash)) return null;

    return openssl_decrypt($ciphertext, $method, $key, OPENSSL_RAW_DATA, $iv);
  }

}
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
?>
