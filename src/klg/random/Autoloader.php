<?php
namespace klg\random;

/**
 * Autoloader for the klg/random package.
 **/
class Autoloader {
  /**
   * Register the autoloader.
   **/
  static public function register() {
    ini_set('unserialize_callback_func', 'spl_autoload_call');
    spl_autoload_register(array(new self, 'autoload'));
  }

  /**
   * The autoload routine.
   * @param string  Fully qualified class name
   **/
  static public function autoload($class) {
    if (0 !== strpos($class, __NAMESPACE__))
      return 0;
    $class = substr($class, strlen(__NAMESPACE__));
    $class = str_replace(
      array('\\','_'), DIRECTORY_SEPARATOR, $class);
    $class = __DIR__ . $class .'.php';
    require $class;
  }
}
