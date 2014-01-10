<?php
namespace klg\random;

/**
 * Convenient wrapper around random generators.
 * Hides all the complexity of generating unpredictable
 * data and provides useful high-level methods.
 **/
class SecureRandom {

  /**
   * Single RBG to be used for everything.
   * @var RandomGenerator
   **/
  protected $source;

  /**
   * Constructor.
   **/
  public function __construct() {
    $this->source = RandomGeneratorFactory::instance();
  }

  /**
   * Get random bytes of given length with full entropy.
   * @param   integer length of data to return
   * @return  string  the string that provides the requested entropy
   **/
  public function get_bytes($length) {
    return $this->source->generate(8*$length);
  }

  /**
   * Reseed PHP native (not secure) RNGs: rand and mt_rand.
   * This will make their states unpredictable but since they are not
   * secure, internal state recovery from their outputs is possible
   * after this.
   **/
  public function php_reseed() {
    $a = unpack('i2', $this->get_bytes(2 * PHP_INT_SIZE));
    srand($a[1] ^ mt_rand() ^ rand());
    mt_srand($a[2] ^ mt_rand() ^ rand());
  }

  /**
   * Random unsigned integer in given range.
   * @param   integer minimal value
   * @param   integer maximal value
   * @return  integer integer between min and max inclusive
   **/
  public function get_integer($min = 0, $max = 0xffffffff) {
    if (($range = $max-$min+1) < 1)
      return $max;
    $i = 1;
    do
      if (--$i < 1) {
        $a = unpack('L*', $this->get_bytes(12));
        $i = count($a);
      }
    while ($a[$i] >= 0x100000000 - (0x100000000 % $range));
    return $min + ($a[1] % $range);
  }

  /**
   * Random unique identifier.
   * This method mimics the PHP function of the same name.
   * It has the same output format, but instead of using
   * time, it stuffs it with full entropy content.
   * @param   string  prefix for generated string
   * @param   boolean if true output will be longer
   * @return  string  unique identifier
   **/
  public function uniqid($prefix = "", $more_entropy = false) {
    if ($more_entropy)
      $more_entropy = sprintf('%.8f',
        $this->get_integer(0,999999999)/100000000);
    $prefix .= substr(sha1($prefix . $more_entropy .
      $this->source->generate(104)), 0, 13);
    return $prefix . $more_entropy;
  }

  /**
   * Shuffle array creating random permutation.
   * Result contains all of the values from the source array
   * but all keys are numerical.  All permutations are equiprobable.
   * @param   array array with values to be permuted
   * @return  array permuted array
   **/
  public function shuffle($a) {
    $a = array_values($a);
    $i = count($a);
    while ($i-- > 1) {
      $j = $this->get_integer(0, $i);
      $x = $a[$i];
      $a[$i] = $a[$j];
      $a[$j] = $x;
    }
    return $a;
  }

  /**
   * Generate secure token using hexadecimal characters.
   * @param   integer length of token in characters
   * @return  string  secure token
   **/
  public function token_hex($length = 40) {
    $x = $this->source->generate($length * 4);
    return substr(bin2hex($x), 0, $length);
  }

  /**
   * Generate secure token using Base64 alphabet.
   * @param   integer length of token in characters
   * @return  string  secure token
   **/
  public function token_base64($length) {
    $x = $this->source->generate($length * 6);
    $x = base64_encode($x);
    return substr($x, 0, $length);
  }

  /**
   * Generate secure token using Base64url [RFC4648] alphabet.
   * @param   integer length of token in characters
   * @return  string  secure token
   **/
  public function token_base64url($length) {
    return strtr($this->token_base64($length), '+/', '-_');
  }

  /**
   * Generate secure token of using alphabet of
   * crypt function. [./0-9A-Za-z].
   * @param   integer length of token in characters
   * @return  string  secure token
   **/
  public function token_crypt($length) {
    return strtr($this->token_base64($length), '+', '.');
  }

  /**
   * Prepare a salt for crypt PHP function.
   * NOTE: It is not recommended to provide a salt to crypt function
   *  at all, it should be generated internally not in PHP code.
   *  It is only needed to explicitly select algorithm which could
   *  be better done in configuration. Also, contrary to popular belief,
   *  salt does not have to be cryptographically secure so this is an
   *  overkill.  While there's nothing wrong with using this function,
   *  it shall never be needed.
   * @param   string  ID or name of an algorithm
   * @param   integer security parameter dependent on algorithm
   * @return  string  salt appropriate for selected algorithm
   **/
  public function salt($type = '2y', $security = null) {
    if ($type[0] === '$') {
      $type = substr($type, 1);
      if ($i = strpos($type, '$'))
        $type = substr($type, 0, $i);
    }

    switch ($type = strtolower($type)) {
    case 'des-ext': case 'ext-des':
      // CRYPT_EXT_DES
      $alpha = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
      if (!$security)
        $security = 100000;
      if ($security < 1)
        $security = 1;
      if ($security > 16777215)
        $security = 16777215;
      for ($s = '_', $i = 0; $i < 4; $i++) {
        $s .= substr($alpha, $security % 64, 1);
        $security = floor($security / 64);
      }
      return $s . $this->token_crypt(4);

    case '0': case 'des': case 'std-des': case 'crypt':
      // CRYPT_STD_DES
      return $this->token_crypt(2);

    case '1': case 'md5':
      // CRYPT_MD5
      return '$1$'.$this->token_crypt(8).'$';

    case '5': case 'sha256': case 'sha-256':
      // CRYPT_SHA256
      $type = '5';
    case '6': case 'sha512': case 'sha-512':
    case 'sha': case 'sha2':
      // CRYPT_SHA512
      if ($type !== '5')
        $type = '6';
      if ($security) {
        if ($security < 1000)
          $security = 1000;
        if ($security > 999999999)
          $security = 999999999;
        $security = 'rounds='.$security.'$';
      }
      return '$'.$type.'$' . $security . $this->token_crypt(16);

    case '2y': case 'blowfish': case 'bcrypt':
    default:
      // CRYPT_BLOWFISH
      $type = '2y';
    case '2x':
    case '2a':
      if (!$security)
        $security = 11;
      if ($security > 31)
        $security = 31;
      if ($security < 4)
        $security = 4;
      return sprintf('$%s$%02u$%s',
        $type, $security, $this->token_crypt(22));
    }
  }
}
