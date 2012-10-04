<?php
namespace klg\random;

/**
 * RBG provided by Mcrypt extension.
 **/
class McryptGenerator implements RandomGenerator {

  public function __construct() {
    if (!function_exists('mcrypt_create_iv'))
      throw new RBGException('No mcrypt_create_iv available');
    if (substr(PHP_OS, 0, 3) === 'WIN')
      if (version_compare(PHP_VERSION, '5.3.0') < 0)
        throw new RBGException('No secure generator available in Mcrypt');
  }

  public function generate($bits, $strength = 0) {
    if ($strength > $bits)
      throw new RBGException('Security strength too high');
    $len = ceil($bits / 8);
    $buf = mcrypt_create_iv($len, MCRYPT_DEV_URANDOM);
    if (strlen($buf)*8 < $strength)
      throw new RBGException('Mcrypt failed to provide requested amount of bits');
    return $buf;
  }
}
