<?php
namespace klg\random;

/**
 * DRBG provided by operating system as urandom(4) device.
 **/
class KernelGenerator implements RandomGenerator {

  /** Path to device.  */
  const PATH = '/dev/urandom';

  /**
   * Device.
   * @var resource
   **/
  protected $dev = null;

  /**
   * Open the device.
   * @return resource opened device
   **/
  protected function open() {
    if ($this->dev)
      return $this->dev;
    $this->dev = @fopen(self::PATH, 'rb');
    if (!$this->dev)
      throw new RBGException('Can not open '. self::PATH);
    if (function_exists('stream_set_read_buffer'))
      @stream_set_read_buffer($this->dev, 0);
  }

  /**
   * Close the device.
   **/
  protected function close() {
    if ($this->dev)
      @fclose($this->dev);
    $this->dev = null;
  }

  public function __construct() {
    $this->open();
  }

  public function __destruct() {
    $this->close();
  }

  public function __sleep() {
    return array();
  }

  public function __wakeup() {
    $this->open();
  }

  public function generate($bits, $strength = 0) {
    if ($strength > $bits)
      throw new RBGException('Security strength too high');
    $dev = $this->open();
    $len = ceil($bits / 8);
    $buf = @fread($dev, $len);
    if ($buf === false || strlen($buf)*8 < $strength)
      throw new RBGException('Device failed to provide requested amount of bits');
    return $buf;
  }

}
