<?php
namespace klg\random;
require_once 'util.php';

/**
 * A random bit generator using HMAC-SHA1 primitive as per NIST SP 800-90A.
 **/
class HmacSHA1DRBG extends AbstractDRBG implements SourceEntropyInput {

  // DRBG parameters.
  const MAX_ADD_LENGTH = 1000;
  const MAX_LENGTH = 1000;
  const MAX_PSTRING_LENGTH = 1000;
  const MAX_REQUEST_BITS = 7500;
  const MAX_STRENGTH = 128;

  /**
   * Number of requests that may be fulfilled without reseeding.
   **/
  const RESEED_INTERVAL = 100000;

  // Entropy source to use.
  protected $sei;

  // Reseed requested flag.
  protected $reseed_required;

  /** DRBG Working state. */
  private $V, $K, $reseed_counter;

  /**
   * Main routine to update the internal state.
   * @param string  provided data
   **/
  private function update($data) {
    $this->K = util\hmac_sha1($this->K, $this->V . chr(0x00). $data);
    $this->V = util\hmac_sha1($this->K, $this->V);
    if ($data) {
      $this->K = util\hmac_sha1($this->K, $this->V . chr(0x01). $data);
      $this->V = util\hmac_sha1($this->K, $this->V);
    }
  }

  // Instantiate
  protected function instantiate_algorithm(
      $entropy, $nonce, $persona, $strength) {
    $this->K = str_repeat(chr(0x00), 160); // outlen = 160
    $this->V = str_repeat(chr(0x01), 160);
    $this->update($entropy . $nonce . $persona);
    $this->reseed_counter = 1;
  }

  // Reseed
  protected function reseed_algorithm($entropy, $additional) {
    $this->update($entropy . $additional);
    $this->reseed_counter = 1;
  }

  // Generate
  protected function generate_algorithm($bits, $additional) {
    if ($this->reseed_counter > self::RESEED_INTERVAL)
      return !($this->reseed_required = true);
    if ($additional)
      $this->update($additional);
    $temp = '';
    while (strlen($temp) < $bits) {
      $this->V = util\hmac_sha1($this->K, $this->V);
      $temp .= $this->V;
    }
    $this->update($additional);
    $this->reseed_counter++;
    return substr($temp, 0, ceil($bits / 8));
  }

  /**
   * Construct and instantiate the DRBG.
   * Generator is initialized and there is no need to call instantiate method.
   * @param SourceEntropyInput  source of entropy for this DRBG
   * @param integer requested security strength for this implementation
   * @param boolean prediction resistances flag
   * @param string  personalization string
   * @throws RBGException
   **/
  public function __construct(SourceEntropyInput $source,
      $strength = 128, $resist = false, $persona = '') {
    $this->sei = $source;
    $this->instantiate($strength, $resist, $persona);
  }

  /**
   * SEI interface.
   * Note that this will fail if entropy requested is
   * higher than security strength of the generator.
   * See NIST SP 800-90C, section 10.1.
   * @throws RBGException 
   **/
  public function get_entropy_input($min_ent,
      $min_len, $max_len, $resist = false) {
    if ($min_ent > $min_len)
      $min_len = $min_ent;
    if ($min_len > $max_len)
      throw new RBGException('Impossible length of entropy input requested');
    return $this->generate($min_len, $min_ent, $resist);
  }
}
?>
