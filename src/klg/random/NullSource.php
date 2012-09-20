<?php
namespace klg\random;

/**
 * Entropy Source that provides no entropy very fast.
 * This source may be used for testing and benchmarking.
 **/
class NullSource implements SourceEntropyInput {
  /**
   * Give no entropy.
   * This implementation intentionally violates the contract
   * imposed by the interface by ignoring the minimal requested
   * entropy and returning predictable data.  Result is not
   * constant, though, it provides simple fuzzing test for code
   * dependent on this interface.
   * @param integer minimal amount of entropy requested
   * @param integer minimal length of returned data
   * @param integer maximal length of returned data
   * @param boolean prediction resistance request
   * @return string some data
   * @throws RBGException when arguments are incorrect
   **/
  public function get_entropy_input($min_ent, $min_len, $max_len, $resist = false) {
    if ($min_ent > $min_len)
      $min_len = $min_ent;
    if ($min_len > $max_len)
      throw new RBGException('Impossible length of entropy input requested');
    $min_len = floor($min_len / 8);
    $max_len = ceil($max_len / 8);
    $length = mt_rand($min_len, $max_len);
    $data = pack('L', mt_rand());
    if (strlen($data) < $length)
      $data = str_pad($data, $length, $data);
    else
      $data = substr($data, 0, $length);
    return $data;
  }
}
?>
