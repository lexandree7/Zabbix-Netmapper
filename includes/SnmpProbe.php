<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Parallel SNMPv1/v2c GET to many hosts and communities using a single UDP socket.
 */
final class SnmpProbe {

	/**
	 * Send errors of the last probe() call: errno => ['message' => string, 'count' => int].
	 */
	public static array $send_errors = [];

	public const SYSTEM_OIDS = [
		'descr' => '1.3.6.1.2.1.1.1.0',
		'objectid' => '1.3.6.1.2.1.1.2.0',
		'name' => '1.3.6.1.2.1.1.5.0',
		'location' => '1.3.6.1.2.1.1.6.0',
		'services' => '1.3.6.1.2.1.1.7.0'
	];

	/**
	 * @param string[] $ips
	 * @param string[] $communities
	 * @param int      $version      1 or 2
	 *
	 * @return array  ip => ['version' => int, 'community_index' => int, 'system' => [...]]
	 */
	public static function probe(array $ips, array $communities, int $version, int $timeout_ms, int $retries,
			bool $fallback_v1 = true): array {
		$found = [];
		self::$send_errors = [];

		if (!$ips || !$communities) {
			return $found;
		}

		$versions = ($version == 1) ? [1] : ($fallback_v1 ? [2, 1] : [2]);

		foreach ($versions as $snmp_version) {
			$pending = array_values(array_diff($ips, array_keys($found)));

			if (!$pending) {
				break;
			}

			for ($try = 0; $try <= $retries && $pending; $try++) {
				$found += self::round($pending, $communities, $snmp_version, $timeout_ms);
				$pending = array_values(array_diff($pending, array_keys($found)));
			}
		}

		return $found;
	}

	private static function round(array $ips, array $communities, int $version, int $timeout_ms): array {
		$socket = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

		if ($socket === false) {
			return [];
		}

		socket_set_nonblock($socket);

		$requests = [];
		$found = [];
		$oids = array_values(self::SYSTEM_OIDS);

		foreach ($ips as $ip) {
			foreach ($communities as $index => $community) {
				$reqid = random_int(1, 0x7FFFFFFF);
				$requests[$reqid] = [$ip, $index];
				$packet = Ber::encodeRequest($version == 1 ? 0 : 1, $community, Ber::PDU_GET, $reqid, 0, 0, $oids);
				if (@socket_sendto($socket, $packet, strlen($packet), 0, $ip, SnmpV12Session::$port) === false) {
					$errno = socket_last_error($socket);
					socket_clear_error($socket);

					if (!array_key_exists($errno, self::$send_errors)) {
						self::$send_errors[$errno] = ['message' => trim(socket_strerror($errno)), 'count' => 0];
					}

					self::$send_errors[$errno]['count']++;
				}
			}

			// Gentle pacing for small OT devices.
			usleep(1000);
		}

		$deadline = microtime(true) + $timeout_ms / 1000;

		while (($left = $deadline - microtime(true)) > 0 && count($found) < count($ips)) {
			$read = [$socket];
			$write = null;
			$except = null;
			$sec = (int) $left;

			if (@socket_select($read, $write, $except, $sec, (int) (($left - $sec) * 1000000)) < 1) {
				break;
			}

			while (true) {
				$buffer = '';
				$from = '';
				$port = 0;

				if (@socket_recvfrom($socket, $buffer, 65535, 0, $from, $port) === false || $buffer === '') {
					break;
				}

				$response = Ber::decodeResponse($buffer);

				if ($response === null || !array_key_exists($response['reqid'], $requests)) {
					continue;
				}

				[$ip, $index] = $requests[$response['reqid']];

				if (array_key_exists($ip, $found) && $found[$ip]['community_index'] <= $index) {
					continue;
				}

				$system = [];
				$by_oid = array_flip(self::SYSTEM_OIDS);

				foreach ($response['varbinds'] as [$oid, $type, $value]) {
					if (array_key_exists($oid, $by_oid)) {
						$system[$by_oid[$oid]] = $value;
					}
				}

				// SNMPv1 agents answer with noSuchName for the whole PDU when one OID is missing; still alive.
				$found[$ip] = [
					'version' => $version,
					'community_index' => $index,
					'system' => self::formatSystem($system)
				];
			}
		}

		socket_close($socket);

		return $found;
	}

	public static function formatSystem(array $system): array {
		return [
			'sysdescr' => Util::text($system['descr'] ?? '', 1024),
			'sysobjectid' => is_string($system['objectid'] ?? null) ? ltrim($system['objectid'], '.') : '',
			'sysname' => Util::text($system['name'] ?? '', 255),
			'syslocation' => Util::text($system['location'] ?? '', 255),
			'sysservices' => (int) ($system['services'] ?? 0)
		];
	}
}
