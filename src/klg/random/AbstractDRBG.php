<?php
namespace klg\random;

/**
 * Abstract random bit generator as per NIST SP 800-90A.
 * This code closely follows the pseudocode "envelope" for
 * DRBG mechanisms as used in SP 800-90A.
 **/
abstract class AbstractDRBG implements RandomGenerator {
  /**
   * The highest supported security strength.
   * Must be overridden by extending class by the means of late static binding.
   **/
  const MAX_STRENGTH = 0;

  /**
   * Maximal length for personalization string in bits.
   * Must be overridden by extending class by the means of late static binding.
   **/
  const MAX_PSTRING_LENGTH = 0;

  /**
   * Maximum entropy input length.
   * Must be overridden by extending class by the means of late static binding.
   **/
  const MAX_LENGTH = 0;

  /**
   * Maximal length of additional input in bits.
   * Must be overridden by extending class by the means of late static binding.
   **/
  const MAX_ADD_LENGTH = 0;

  /**
   * Maximal number of bits per request.
   * Must be overridden by extending class by the means of late static binding.
   **/
  const MAX_REQUEST_BITS = 0;

  /**
   * Entropy source to use for seeding.
   * @var SourceEntropyInput
   **/
  protected $sei;

  /**
   * Security strength.
   * @var integer
   **/
  protected $strength;

  /**
   * Prediction resistance flag.
   * @var boolean
   **/
  protected $resist;

  /**
   * Reseed required flag.
   * @var boolean
   **/
  protected $reseed_required = false;

  /**
   * Envelope for instantiation algorithm.
   * Determine mechanism specific parameters and
   * determine the initial working state.
   * @param string  bitstring obtained from the SEI
   * @param string  nonce
   * @param string  personalization string
   * @param integer security strength for the instantiation
   **/
  abstract protected function instantiate_algorithm(
    $entropy, $nonce, $persona, $strength);

  /**
   * Initialize the state of DRBG.
   * It probably should be called from constructor during object instantiation.
   * Because acquisition of proper nonce is problematic from PHP, this
   * implementation uses "extra strong" entropy input instead of nonce
   * as described in SP 800-90A, section 8.6.7.
   * @param integer requested security strength
   * @param boolean prediction resistance flag
   * @param string  personalization string
   * @throws RBGException
   **/
  public function instantiate($strength, $resist = false, $persona = '') {
    if ($strength > static::MAX_STRENGTH)
      throw new RBGException('Requested security strength not supported');
    if (strlen($persona) > ceil(static::MAX_PSTRING_LENGTH / 8))
      throw new RBGException('Personalization string too long');
    if ($strength <= 112)
      $strength = 112;
    elseif ($strength <= 128)
      $strength = 128;
    elseif ($strength <= 192)
      $strength = 192;
    else
      $strength = 256;
    try {
      // try the entropy + nonce in single call
      $input = $this->sei->get_entropy_input($strength * 3/2,
        $strength, static::MAX_LENGTH, $resist);
      $nonce = null;
    }
    catch (RBGException $ex) {
      // it may have failed because request was too large
      $input = $this->sei->get_entropy_input($strength,
        $strength, static::MAX_LENGTH, $resist);
      $nonce = $this->sei->get_entropy_input(ceil($strength / 2),
        $strength, static::MAX_LENGTH, $resist);
    }
    $this->strength = $strength;
    $this->resist = (boolean) $resist;
    $this->instantiate_algorithm($input, $nonce, $persona, $strength);
  }

  /**
   * Envelope for reseeding algorithm.
   * Combine current working state with new entropy
   * input and any additional input.
   * @param string  bitstring obtained from the SEI
   * @param string  additional input string received from consuming application
   **/
  abstract protected function reseed_algorithm($entropy, $additional);

  /**
   * Reseed the DRBG.
   * @param boolean prediction resistance request
   * @param string  additional input
   * @throws RBGException
   **/
  public function reseed($resist = false, $add = '') {
    if ($resist && !$this->resist)
      throw new RBGException('DRBG not initialized for prediction resistance');
    if (strlen($add) > ceil(static::MAX_ADD_LENGTH / 8))
      throw new RBGException('Additional input too long');
    $input = $this->sei->get_entropy_input($this->strength,
      $this->strength, static::MAX_LENGTH, $resist);
    $this->reseed_algorithm($input, $add);
  }

  /**
   * Envelope for generating algorithm.
   * Generate requested pseudorandom bits.  In case there is no
   * sufficient entropy, this method shall set $reseed_required flag
   * and return an empty string.
   * @param integer prediction resistance request
   * @param string  additional input string received from consuming application
   * @return  string  bitstring containing generated data
   **/
  abstract protected function generate_algorithm($bits, $additional);

  /**
   * Generate pseudorandom bits.
   * @param   integer requested number of bits
   * @param   integer requested security strength
   * @param   boolean prediction resistance request
   * @param   string  additional input
   * @return  string  returned bits
   * @throws RBGException
   **/
  public function generate($bits, $strength = 0, $resist = false, $add = '') {
    if ($bits > static::MAX_REQUEST_BITS)
      throw new RBGException('Too many bits requested');
    if ($strength > $this->strength)
      throw new RBGException('Security strength too high');
    if (strlen($add) > ceil(static::MAX_ADD_LENGTH / 8))
      throw new RBGException('Additional input too long');
    if ($resist && !$this->resist)
      throw new RBGException('DRBG not initialized for prediction resistance');
    if ($strength < 1) // default max
      $strength = $this->strength;
    do {
      if ($this->reseed_required || $resist) {
        $this->reseed($resist, $add);
        $add = '';
        $this->reseed_required = false;
      }
      $data = $this->generate_algorithm($bits, $add);
      if ($this->resist)
        $resist = true;
    } while ($this->reseed_required);
    return $data;
  }
}
