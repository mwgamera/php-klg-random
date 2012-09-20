<?php
namespace klg\random;
require_once 'util.php';

/**
 * Pure PHP portable NRBG.
 * It does not require any extensions or system specific features.
 * An Enhanced NRBG - Oversampling Construction is used to derive full
 * entropy data from PHPNativeSEI which may have low entropy rate.
 * See NIST SP 800-90C, section 9.3.
 **/
class PHPNativeGenerator implements RandomGenerator, SourceEntropyInput {

  /**
   * Internal DRBG seeded from live entropy source.
   * @var AbstractDRBG
   **/
  private $drbg;

  /**
   * Security strength of DRBG.
   * @var integer
   **/
  public $strength;

  /**
   * Create and instantiate NRBG.
   * @param string  optional personalization string
   * @throws RBGException
   **/
  public function __construct($persona = '') {
    $source = new PHPNativeSEI;
    $strength = HmacSHA1DRBG::MAX_STRENGTH;
    $resist = true;
    $persona = self::persona($persona);
    $this->drbg = new HmacSHA1DRBG($source, $strength, $resist, $persona);
    $this->strength = $strength;
  }

  /**
   * Generate random bits.
   * @param   integer requested number of bits
   * @param   integer ignored
   * @param   string  additional input
   * @return  string  returned full entropy bitstring
   * @throws RBGException
   **/
  public function generate($bits, $strength = 0, $add = '') {
    $tmp = '';
    $sum = 0;
    $s = (int) floor($this->strength / 2);
    $resist = true;
    while ($sum < $bits) {
      $tmp .= $this->drbg->generate($s, 2*$s, $resist, $add);
      $sum += $s;
    }
    return substr($tmp, 0, ceil($bits / 8));
  }

  /**
   * SEI interface.
   * @throws RBGException
   **/
  public function get_entropy_input($min_ent,
      $min_len, $max_len, $resist = false) {
    if ($min_ent > $min_len)
      $min_len = $min_ent;
    if ($min_len > $max_len)
      throw new RBGException('Impossible length of entropy input requested');
    return $this->generate($min_len, $min_ent);
  }


  /**
   * Build a personalization string that includes any leftover
   * entropy available in the environment.
   * @param   string  original personalization string given by application
   * @return  string  personalization string to be used for internal DRBG
   **/
  private static function persona($persona) {
    $p = $persona;
    $p.= rand() . uniqid(mt_rand(), true);
    $p.= @memory_get_usage();
    $p.= @serialize($GLOBALS);
    $p.= @implode("\x1f", @array_values(@fstat(@fopen(__FILE__, 'r'))));
    $p.= @microtime();
    $len = HmacSHA1DRBG::MAX_PSTRING_LENGTH;
    $len = ceil($len / 8) * 8;
    return util\sha1_df($p, $len);
  }
}
?>
