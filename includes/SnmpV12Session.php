<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Pure PHP SNMPv1/v2c client based on the "sockets" extension (mandatory for Zabbix frontend).
 */
class SnmpV12Session extends SnmpSession {

	/**
	 * Agent UDP port (161; changed only by automated tests).
	 */
	public static int $port = 161;

	/** @var resource|\Socket */
	private $socket;
	private int $version;
	private string $community;

	public function __construct(string $ip, int $version, string $community, int $timeout_ms, int $retries) {
		$this->ip = $ip;
		$this->version = ($version == 1) ? 1 : 2;
		$this->community = $community;
		$this->timeout_ms = max(200, $timeout_ms);
		$this->retries = max(0, $retries);

		$socket = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

		if ($socket === false) {
			throw new \RuntimeException(_('Cannot create UDP socket.'));
		}

		$this->socket = $socket;
	}

	public function __destruct() {
		if ($this->socket) {
			@socket_close($this->socket);
		}
	}

	public function withCommunity(string $community): ?SnmpSession {
		return new self($this->ip, $this->version, $community, $this->timeout_ms, $this->retries);
	}

	public function getCommunity(): ?string {
		return $this->community;
	}

	public function get(array $oids): array {
		$result = array_fill_keys($oids, null);

		foreach (array_chunk($oids, 10) as $chunk) {
			try {
				$response = $this->request(Ber::PDU_GET, $chunk);
			}
			catch (SnmpTimeoutException $e) {
				if ($chunk === $oids || $result === array_fill_keys($oids, null)) {
					throw $e;
				}

				continue;
			}

			// SNMPv1 fails the whole PDU on noSuchName (2): retry one by one.
			if ($response['error_status'] != 0) {
				if (count($chunk) > 1) {
					foreach ($chunk as $oid) {
						try {
							$single = $this->request(Ber::PDU_GET, [$oid]);

							if ($single['error_status'] == 0 && $single['varbinds']) {
								$result[$oid] = $single['varbinds'][0][2];
							}
						}
						catch (SnmpTimeoutException $e) {
						}
					}
				}

				continue;
			}

			foreach ($response['varbinds'] as [$oid, $type, $value]) {
				if (array_key_exists($oid, $result)) {
					$result[$oid] = $value;
				}
			}
		}

		return $result;
	}

	public function walk(string $base_oid, int $max_rows = 20000): array {
		$base_oid = trim($base_oid, '.');
		$prefix = $base_oid.'.';
		$current = $base_oid;
		$result = [];
		$deadline = microtime(true) + 60;

		while (count($result) < $max_rows && microtime(true) < $deadline) {
			$response = ($this->version == 1)
				? $this->request(Ber::PDU_GETNEXT, [$current])
				: $this->request(Ber::PDU_GETBULK, [$current], 0, 25);

			if ($response['error_status'] != 0 || !$response['varbinds']) {
				break;
			}

			$last = null;

			foreach ($response['varbinds'] as [$oid, $type, $value]) {
				if ($type == Ber::T_ENDOFMIBVIEW || strpos($oid, $prefix) !== 0) {
					return $result;
				}

				// Agent loop protection: OIDs must increase.
				if (Ber::compareOids($oid, $current) <= 0) {
					return $result;
				}

				$result[$oid] = $value;
				$current = $last = $oid;
			}

			if ($last === null) {
				break;
			}
		}

		return $result;
	}

	private function request(int $pdu, array $oids, int $a = 0, int $b = 0): array {
		$reqid = random_int(1, 0x7FFFFFFF);
		$version_code = ($this->version == 1) ? 0 : 1;
		$packet = Ber::encodeRequest($version_code, $this->community, $pdu, $reqid, $a, $b, $oids);

		for ($try = 0; $try <= $this->retries; $try++) {
			if (@socket_sendto($this->socket, $packet, strlen($packet), 0, $this->ip, self::$port) === false) {
				$errno = socket_last_error($this->socket);
				socket_clear_error($this->socket);

				throw new SnmpTransportException(sprintf('Cannot send SNMP request to %s: %s (errno %d).', $this->ip,
					trim(socket_strerror($errno)), $errno
				), $errno);
			}

			$deadline = microtime(true) + $this->timeout_ms / 1000;

			while (($left = $deadline - microtime(true)) > 0) {
				$read = [$this->socket];
				$write = null;
				$except = null;
				$sec = (int) $left;

				if (@socket_select($read, $write, $except, $sec, (int) (($left - $sec) * 1000000)) < 1) {
					break;
				}

				$buffer = '';
				$from = '';
				$port = 0;

				if (@socket_recvfrom($this->socket, $buffer, 65535, 0, $from, $port) === false) {
					break;
				}

				$response = Ber::decodeResponse($buffer);

				if ($response !== null && $response['reqid'] == $reqid) {
					return $response;
				}
			}
		}

		throw new SnmpTimeoutException(sprintf('SNMP timeout (%s).', $this->ip));
	}
}
