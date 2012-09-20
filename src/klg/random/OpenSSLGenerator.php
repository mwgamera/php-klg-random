<?php
namespace klg\random;

/**
 * RBG from OpenSSL extension.
 **/
class OpenSSLGenerator implements RandomGenerator {

  public function __construct() {
    if (!function_exists('openssl_random_pseudo_bytes'))
      throw new RBGException('No openssl_random_pseudo_bytes available');
    if (substr(PHP_OS, 0, 3) === 'WIN')
      if (version_compare(PHP_VERSION, '5.3.4') < 0)
        throw new RBGException('Not using openssl_random_pseudo_bytes because of known bugs');
    openssl_random_pseudo_bytes(1, $strong);
    if (!$strong)
      throw new RBGException('No strong generator in OpenSSL');
  }

  public function generate($bits, $strength = 0) {
    if ($strength > $bits)
      throw new RBGException('Security strength too high');
    $len = ceil($bits / 8);
    $buf = openssl_random_pseudo_bytes($len, $strong);
    if ($strength > 0 && !$strong)
      throw new RBGException('OpenSSL failed to provide requested strength');
    if (strlen($buf)*8 < $strength)
      throw new RBGException('OpenSSL failed to provide requested amount of bits');
    return $buf;
  }
}
?>
