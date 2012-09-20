<?php
namespace klg\random;

/**
 * Generic interface for Random Bit Generator (RBG).
 * It can be used both with NRBG and DRBG.  Only the generate
 * function is required because in most cases it's going to be
 * an interface to externally managed generator which does not
 * expose its instantiation or reseeding methods.
 **/
interface RandomGenerator {
  /**
   * Generate random bits.
   * This method should be conceptually identical with RBG_Generate
   * function which NIST SP 800-90C refused to specify referring only
   * to ANSI X9.82, Part 4. (X9.82 is on my wishlist, if you like my
   * code you can buy me a copy of it.)
   * @param   integer requested number of bits
   * @param   integer requested security strength
   * @return  string  returned bits
   * @throws RBGException
   **/
  public function generate($bits, $strength = 0);
}
?>
