<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Host liveness detection: ICMP (fping, when available), parallel TCP connect and the ARP cache.
 * TCP probes only open and immediately reset the connection - no payload is sent.
 */
final class Scanner {

	/**
	 * @param string[] $ips
	 *
	 * @return string[]  alive IPs
	 */
	public static function fping(array $ips): array {
		$fping = (string) Config::get('fping_path');

		if (!$ips || $fping === '' || !function_exists('exec') || !@is_executable($fping)) {
			return [];
		}

		$cmd = escapeshellarg($fping).' -a -q -r 1 -t 500 -i 5 '.implode(' ', array_map('escapeshellarg', $ips))
			.' 2>/dev/null';

		$output = [];
		@exec($cmd, $output);

		return array_values(array_intersect(array_map('trim', $output), $ips));
	}

	public static function isFpingAvailable(): bool {
		$fping = (string) Config::get('fping_path');

		return $fping !== '' && function_exists('exec') && @is_executable($fping);
	}

	/**
	 * Parallel non-blocking TCP connect.
	 *
	 * @param string[] $ips
	 * @param int[]    $ports
	 *
	 * @return array  ip => ['open' => int[], 'refused' => bool]
	 */
	public static function tcpProbe(array $ips, array $ports, int $timeout_ms, int $concurrency): array {
		$targets = [];

		foreach ($ips as $ip) {
			foreach ($ports as $port) {
				$targets[] = [$ip, $port];
			}
		}

		$results = [];
		$refused_codes = array_filter([
			defined('SOCKET_ECONNREFUSED') ? SOCKET_ECONNREFUSED : null, 111, 10061
		]);
		$progress_codes = array_filter([
			defined('SOCKET_EINPROGRESS') ? SOCKET_EINPROGRESS : null,
			defined('SOCKET_EWOULDBLOCK') ? SOCKET_EWOULDBLOCK : null,
			defined('SOCKET_EALREADY') ? SOCKET_EALREADY : null, 115, 114, 10035, 10036, 10037
		]);

		// Keep below FD_SETSIZE (1024).
		$concurrency = max(1, min(512, $concurrency));

		foreach (array_chunk($targets, $concurrency) as $batch) {
			$pending = [];

			foreach ($batch as $i => [$ip, $port]) {
				$socket = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

				if ($socket === false) {
					continue;
				}

				socket_set_nonblock($socket);
				// Abort with RST on close: no TIME_WAIT, lowest impact on small embedded TCP stacks.
				@socket_set_option($socket, SOL_SOCKET, SO_LINGER, ['l_onoff' => 1, 'l_linger' => 0]);

				$connected = @socket_connect($socket, $ip, $port);
				$error = socket_last_error($socket);
				socket_clear_error($socket);

				if ($connected) {
					self::mark($results, $ip, $port, true);
					socket_close($socket);
				}
				elseif (in_array($error, $refused_codes, true)) {
					self::mark($results, $ip, $port, false);
					socket_close($socket);
				}
				elseif (in_array($error, $progress_codes, true)) {
					$pending[$i] = [$socket, $ip, $port];
				}
				else {
					socket_close($socket);
				}
			}

			$deadline = microtime(true) + $timeout_ms / 1000;

			while ($pending && ($left = $deadline - microtime(true)) > 0) {
				$write = [];
				$except = [];

				foreach ($pending as $i => [$socket]) {
					$write[$i] = $socket;
					$except[$i] = $socket;
				}

				$read = null;
				$sec = (int) $left;

				if (@socket_select($read, $write, $except, $sec, (int) (($left - $sec) * 1000000)) < 1) {
					break;
				}

				foreach (array_unique(array_merge(array_keys($write), array_keys($except))) as $i) {
					if (!array_key_exists($i, $pending)) {
						continue;
					}

					[$socket, $ip, $port] = $pending[$i];
					$error = @socket_get_option($socket, SOL_SOCKET, SO_ERROR);

					if ($error === 0) {
						self::mark($results, $ip, $port, true);
					}
					elseif (in_array($error, $refused_codes, true)) {
						self::mark($results, $ip, $port, false);
					}

					socket_close($socket);
					unset($pending[$i]);
				}
			}

			foreach ($pending as [$socket]) {
				socket_close($socket);
			}
		}

		return $results;
	}

	private static function mark(array &$results, string $ip, int $port, bool $open): void {
		if (!array_key_exists($ip, $results)) {
			$results[$ip] = ['open' => [], 'refused' => false];
		}

		if ($open) {
			$results[$ip]['open'][] = $port;
		}
		else {
			$results[$ip]['refused'] = true;
		}
	}

	/**
	 * Single TCP connection with timeout, returns a blocking stream or null.
	 *
	 * @return resource|null
	 */
	public static function connect(string $ip, int $port, float $timeout, bool $tls = false) {
		$context = stream_context_create([
			'ssl' => [
				'verify_peer' => false,
				'verify_peer_name' => false,
				'allow_self_signed' => true,
				'capture_peer_cert' => true,
				'SNI_enabled' => false,
				'security_level' => 0
			]
		]);

		$errno = 0;
		$errstr = '';
		$stream = @stream_socket_client(($tls ? 'tls' : 'tcp').'://'.$ip.':'.$port, $errno, $errstr, $timeout,
			STREAM_CLIENT_CONNECT, $context
		);

		if ($stream === false) {
			return null;
		}

		stream_set_timeout($stream, (int) ceil($timeout));

		return $stream;
	}
}
