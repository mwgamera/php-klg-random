<?php
namespace klg\random;

/**
 * Failure of random bit generator to serve the request.
 * Usually thrown when request is invalid or no entropy available.  All the
 * error conditions described in NIST SP 800-90 are signalled using this class.
 **/
class RBGException extends \Exception {} 
?>
