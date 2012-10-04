<?php
/**
 * Utility functions.
 **/
namespace klg\random\util;

// Find usable implementation of HMAC-SHA1.
//
if (function_exists('hash_hmac') && @hash_hmac('sha1','','',true)
    === pack('H*', 'fbdb1d1b18aa6c08324b7d64b71fb76370690e1d')) {
  /**
   * Implementation of RFC 2104 HMAC-SHA1 using Hash PECL extension.
   * @param string  key
   * @param string  message
   * @return  string  message authentication code
   **/
  function hmac_sha1($key, $msg) {
    return hash_hmac('sha1', $msg, $key, true);
  }
}
else {
  /**
   * Native PHP implementation of RFC 2104 HMAC-SHA1.
   * @param string  key
   * @param string  message
   * @return  string  message authentication code
   **/
  function hmac_sha1($key, $msg) {
    $ipad = str_repeat(chr(0x36), 64);
    $opad = str_repeat(chr(0x5C), 64);
    if (strlen($key) > 64)
      $key = sha1($key, true);
    if (strlen($key) < 64)
      $key = str_pad($key, 64, chr(0));
    $ipad ^= $key;
    $opad ^= $key;
    return sha1($opad . sha1($ipad . $msg, true), true);
  }
}

/**
 * Hash_df derivation function based on SHA1.
 * NIST SP 800-90A, section 10.4.1.
 * @param string  source bitstring
 * @param integer number of bits to return
 * @return string bitstring of requested size
 **/
function sha1_df($input, $bits) {
  $tmp = '';
  $len = (int) ceil($bits / 160);
  $ctr = 1;
  for ($i = 0; $i < $len; $i++) {
    $tmp .= sha1(pack('CNa*', $ctr &= 0xff, $bits, $input), true);
    $ctr++;
  }
  $len = (int) ceil($bits / 8);
  if ($i = $bits % 8)
    $tmp[$len-1] = chr((0xff00 >> $i) & ord($tmp[$len-1]));
  $tmp = substr($tmp, 0, $len);
  return $tmp;
}

