<?php
namespace klg\random;

/**
 * Interface for Source of Entropy Input (SEI) as per NIST SP 800-90C.
 **/
interface SourceEntropyInput {
  /**
   * Get entropy from the source.
   * @param   integer the minimum amount of entropy to be provided 
   * @param   integer the minimum length of the output string (bits)
   * @param   integer the maximum length of the output string (bits)
   * @param   boolean provide prediction resistance for this function
   * @return  string  Bitstring returned containing the entropy
   * @throws RBGException
   **/
  public function get_entropy_input($min_ent, $min_len, $max_len, $resist = false);
}
