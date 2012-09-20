<?php
namespace klg\random;
require_once 'util.php';

/**
 * Pure PHP portable entropy source that does not require any
 * extensions or system specific features.
 **/
class PHPNativeSource implements SourceEntropyInput {

  /**
   * Approximate time of sample generation in microseconds.
   **/
  const SAMPLE_TIME = 150;

  /**
   * Number of samples retunred in single get_entropy call.
   **/
  const NOISE_LENGTH = 200;

  /**
   * Number of rounds of SHA1 calculated for single sample.
   * Each sample is a time of execution a loop of that many SHA1 computations.
   * This value is adjusted to approximately meet the SAMPLE_TIME.
   * @var integer
   **/
  private $rounds = 50;

  /**
   * Get raw digitized but unprocessed samples from noise source.
   * @param   integer   number of samples to be obtained
   * @return  integer[] array of integer samples
   **/
  protected function get_noise($samples, $rounds = false) {
    if (!$rounds)
      $rounds = $this->rounds;
    $s1 = array();
    $s2 = array();
    for ($i = 0; $i < $samples; $i++) {
      $c1 = microtime();
      $var = sha1(mt_rand());
      for ($j = 0; $j < $rounds; $j++)
        $var = sha1($var);
      $c2 = microtime();
      $s1[] = $c1;
      $s2[] = $c2;
    }
    $dat = array();
    for ($i = 0; $i < $samples; $i++) {
      $a = preg_match('/^0\.([0-9]{6})[0-9]*\s([0-9]+)$/', $s1[$i], $m1);
      $b = preg_match('/^0\.([0-9]{6})[0-9]*\s([0-9]+)$/', $s2[$i], $m2);
      assert($a && $b);
      $d = ((int)$m2[1] - (int)$m1[1]);
      $d += 1000000 * (((int)$m2[2] - (int)$m1[2]));
      $dat[] = $d;
    }
    return $dat;
  }

  /**
   * Adjust number of rounds to meet requested time.
   * @param integer[] samples
   **/
  private function adjust_rounds($data) {
    $z = array();
    $m = 0;
    $t = $data[0];
    foreach ($data as $x)
      if (@++$z[$x] > $m) {
        $m = $z[$x];
        $t = $x;
      }
    $this->rounds *= self::SAMPLE_TIME / $t;
    $this->rounds = (int) ($this->rounds + 1);
  }

  /**
   * Perform frequency test on given data.
   * @param   integer[] samples
   * @return  float     min-entropy estimate
   **/
  private static function test_frequency($data) {
    $z = array();
    $m = 0;
    foreach ($data as $x)
      if (@++$z[$x] > $m)
        $m = $z[$x];
    $n = count($data);
    $e = sqrt(log(1/.95)/log(2) / (2*$n));
    return -log($m/$n + $e)/log(2);
  }

  /**
   * Assess entropy estimate to given sample data.
   * @param   integer[] samples
   * @return  float     information content of the data set
   **/
  private static function assess_entropy($data) {
    $e = array();
    $e[] = self::test_frequency($data);
    // TODO: add more tests
    $m = $e[0];
    $l = count($e);
    for ($i = 1; $i < $l; $i++)
      if ($e[$i] < $m)
        $m = $e[$i];
    return $m * count($data);
  }

  /**
   * Convert array of samples to binstring.
   * @param   integer[] samples
   * @return  string    bitstring of data
   **/
  private static function sample_convert($data) {
    $s = '';
    foreach ($data as $x) {
      while ($x) {
        $c = $x & 0x7f;
        if ($x & ~0x7f)
          $c |= 0x80;
        $x >>= 7;
        $s .= chr($c);
      }
    }
    return $s;
  }

  /**
   * Get entropy.
   * @param   integer  assessed entropy (out)
   * @return  string    entropy bitstring
   **/
  public function get_entropy(&$entropy) {
    $noise = $this->get_noise(self::NOISE_LENGTH);
    $entropy = self::assess_entropy($noise);
    return self::sample_convert($noise);
  }

  /**
   * SEI interface to this entropy source.
   * See NIST SP 800-90C, section 10.2.
   **/
  public function get_entropy_input($min_ent, $min_len, $max_len, $resist = false) {
    if ($min_len > $max_len)
      throw new RBGException('Impossible length of entropy input requested');
    $this->adjust_rounds($this->get_noise(5));
    $tmp = '';
    $sum_ent = 0;
    while ($sum_ent < $min_ent) {
      $ass_ent = 0;
      $tmp .= $this->get_entropy($ass_ent);
      $sum_ent += $ass_ent;
    }
    $n = 8*strlen($tmp);
    if ($n < $min_len)
      $tmp = str_pad($tmp, ceil($min_len / 8), chr(0x00));
    if ($n > $max_len)
      $tmp = util\sha1_df($tmp, $max_len);
    return $tmp;
  }
}
?>
