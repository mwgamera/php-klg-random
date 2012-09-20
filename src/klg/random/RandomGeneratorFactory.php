<?php
namespace klg\random;
require_once 'util.php';

/**
 * Static factory that knows about all available RBGs and their
 * configuration and can instantiate the best one by itself.
 **/
class RandomGeneratorFactory {

  /**
   * List of known RBGs in order they should be tried.
   * @var string[]
   **/
  protected static $registry =
    array('OpenSSL', 'Mcrypt', 'EGD', 'Kernel', 'PHPNative');

  /**
   * Cached instance of the best RBG.
   * @var RandomGenerator
   **/
  protected static $instance = null;

  /**
   * Get the best generator available.
   * @return RandomGenerator
   * @throws RBGException When no RBG could be instantiated
   **/
  public static function instance() {
    foreach (self::$registry as $name) {
      try {
        return call_user_func("self::instance_$name");
      }
      catch (RBGException $x) {}
    }
    throw new RBGException('No working implementation found');
  }

  /**
   * Get instance of OpenSSLGenerator.
   * @return RandomGenerator
   **/
  protected static function instance_OpenSSL() {
    return new OpenSSLGenerator;
  }

  /**
   * Get instance of McryptGenerator.
   * @return RandomGenerator
   **/
  protected static function instance_Mcrypt() {
    return new McryptGenerator;
  }

  /**
   * Get instance of EGDGenerator.
   * @return RandomGenerator
   **/
  protected static function instance_EGD() {
    return new EGDGenerator;
  }

  /**
   * Get instance of KernelGenerator.
   * @return RandomGenerator
   **/
  protected static function instance_Kernel() {
    return new KernelGenerator;
  }

  /**
   * Get instance of PHPNativeGenerator.
   * PHPNativeGenerator is painfully slow because it has to gather all the
   * entropy by itself, therefore it's additionally wrapped in HMAC_DRBG.
   * @return RandomGenerator
   **/
  protected static function instance_PHPNative() {
    return new HmacSHA1DRBG(new PHPNativeGenerator(self::persona()));
  }

  /**
   * Build a personalization string that includes any leftover
   * entropy available in the environment.
   * @return  string  personalization string to be used for internal DRBG
   **/
  private static function persona() {
    $p = rand() . uniqid(mt_rand(), true);
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
