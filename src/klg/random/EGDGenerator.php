<?php
namespace klg\random;

/**
 * Acquire RBG output using the Entropy Gathering Daemon protocol.
 **/
class EGDGenerator implements RandomGenerator {

  /**
   * Array of possible addresses for EGD socket.
   * @var string[]
   **/
  public $search = array(
    "/var/run/egd-pool",
    "/dev/egd-pool",
    "/etc/egd-pool");

  /**
   * Connected socket.
   * @var resource
   **/
  protected $sock = null;

  /**
   * Name of the connected peer.
   * @var string
   **/
  protected $peer = null;

  /**
   * Try opening EGD socket to given address.
   * Address might be either: 1. local path for Unix-domain socket,
   * 2. TCP/IP address in the format "tcp/hostname:port".
   * @param string address
   * @return resource opened socket or null on failure
   **/
  private static function try_open($address) {
    if (preg_match('/tcp\/(.*):([0-9]+)/i', $address, $m)) {
      $s = socket_create(AF_INET6, SOCK_STREAM, 0);
      if (@socket_connect($s, $m[1], (int)$m[2]))
        return $s;
      socket_close($s);
      $s = socket_create(AF_INET, SOCK_STREAM, 0);
      if (@socket_connect($s, $m[1], (int)$m[2]))
        return $s;
      socket_close($s);
    }
    else {
      $s = socket_create(AF_UNIX, SOCK_STREAM, 0);
      if (@socket_connect($s, $a)) return $s;
      socket_close($s);
    }
    return null;
  }

  /**
   * Open the socket to the first address from the search list that works.
   * @return resource opened socket
   **/
  protected function open() {
    if ($this->sock)
      return $this->sock;
    foreach ($this->search as $addr)
      if ($this->sock = self::try_open($addr)) {
        $port = false;
        socket_getpeername($this->sock, $this->peer, $port);
        if ($port) $this->peer .= ':'.$port;
        return $this->sock;
      }
    throw new RBGException('Can not find EGD socket');
  }

  /**
   * Close the socket.
   **/
  protected function close() {
    if ($this->sock)
      socket_close($this->sock);
    $this->sock = null;
    $this->peer = null;
  }

  /**
   * Constructor.
   * Optionally custom path to be checked may be
   * provided as a string or array of strings.
   * @param mixed search paths
   **/
  public function __construct($address = null) {
    if ($address)
      if (is_array($address))
        $this->search = array_merge($address, $this->search);
      else
        array_unshift($this->search, $address);
    $this->open();
  }

  public function __destruct() {
    $this->close();
  }

  public function __sleep() {
    return array('search');
  }

  public function __wakeup() {
    $this->open();
  }

  public function generate($bits, $strength = 0) {
    if ($strength > $bits)
      throw new RBGException('Security strength too high');
    $len = ceil($bits / 8);
    try {
      $sock = $this->open();
      if (socket_write($sock, pack('C2', 2, $len), 2) === false)
        throw new RBGException;
      if (($buf = socket_read($sock, $len)) === false)
        throw new RBGException;
    }
    catch (RBGException $ex) {
      $peer = $this->peer;
      $this->close();
      throw new RBGException('Error communicating with EGD at '.$peer);
    }
    if ($buf === false || strlen($buf)*8 < $strength)
      throw new RBGException('EGD failed to provide requested amount of bits');
    return $buf;
  }
}
?>
