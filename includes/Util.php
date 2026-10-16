<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Small helpers for IP / MAC / interface name handling and safe text output.
 */
final class Util {

	public static function isIpv4($ip): bool {
		return is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
	}

	/**
	 * Converts 6 raw bytes into "aa:bb:cc:dd:ee:ff".
	 */
	public static function macFromBin($bin): ?string {
		if (!is_string($bin) || strlen($bin) != 6) {
			return null;
		}

		return implode(':', str_split(bin2hex($bin), 2));
	}

	/**
	 * Normalizes textual MAC representations (aa:bb:.., aa-bb-.., aabb.ccdd.eeff, "AA BB CC ..", aabbccddeeff).
	 */
	public static function normalizeMac($value): ?string {
		if (!is_string($value)) {
			return null;
		}

		$value = trim($value, " \t\r\n\"");

		if (preg_match('/^([0-9a-f]{1,2})[:\- ]([0-9a-f]{1,2})[:\- ]([0-9a-f]{1,2})[:\- ]([0-9a-f]{1,2})[:\- ]([0-9a-f]{1,2})[:\- ]([0-9a-f]{1,2})$/i',
				$value, $m)) {
			$hex = '';

			for ($i = 1; $i <= 6; $i++) {
				$hex .= str_pad($m[$i], 2, '0', STR_PAD_LEFT);
			}
		}
		elseif (preg_match('/^[0-9a-f]{4}[.\-][0-9a-f]{4}[.\-][0-9a-f]{4}$/i', $value)
				|| preg_match('/^[0-9a-f]{6}-[0-9a-f]{6}$/i', $value)
				|| preg_match('/^[0-9a-f]{12}$/i', $value)) {
			$hex = preg_replace('/[^0-9a-f]/i', '', $value);
		}
		else {
			return null;
		}

		$hex = strtolower($hex);

		if ($hex === '000000000000' || $hex === 'ffffffffffff') {
			return null;
		}

		return implode(':', str_split($hex, 2));
	}

	/**
	 * MAC from an SNMP octet string value that may be raw (6 bytes) or already textual (ext-snmp).
	 */
	public static function macFromSnmp($value): ?string {
		if (!is_string($value)) {
			return null;
		}

		if (strlen($value) == 6) {
			$mac = self::macFromBin($value);

			return ($mac === '00:00:00:00:00:00') ? null : $mac;
		}

		return self::normalizeMac($value);
	}

	/**
	 * Converts arbitrary device output into a JSON-safe printable string.
	 */
	public static function text($value, int $max = 2048): string {
		if ($value === null || $value === false) {
			return '';
		}

		if (!is_string($value)) {
			return (string) $value;
		}

		$value = rtrim($value, "\0");

		if ($value === '') {
			return '';
		}

		if (preg_match('/[\x00-\x08\x0e-\x1f]/', $value)) {
			// Binary content: show as hex.
			return implode(':', str_split(bin2hex(substr($value, 0, 64)), 2));
		}

		if (!mb_check_encoding($value, 'UTF-8')) {
			$value = mb_convert_encoding($value, 'UTF-8', 'ISO-8859-1');
		}

		$value = trim(str_replace("\r", '', $value));

		return mb_strlen($value) > $max ? mb_substr($value, 0, $max).'…' : $value;
	}

	/**
	 * Removes ANSI/VT100 escape sequences and backspaces from terminal output.
	 */
	public static function stripAnsi(string $text): string {
		$text = preg_replace('/\x1b\[[0-9;?]*[ -\/]*[@-~]/', '', $text);
		$text = preg_replace('/\x1b[()][A-Za-z0-9]|\x1b[=>78DEHMc]/', '', $text);

		// Resolve backspaces ("abc\x08\x08" -> "a").
		while (strpos($text, "\x08") !== false) {
			$new = preg_replace('/[^\x08\n]\x08/', '', $text, 1);

			if ($new === $text) {
				$text = str_replace("\x08", '', $text);
				break;
			}

			$text = $new;
		}

		return str_replace(["\r\n", "\r", "\0"], ["\n", "\n", ''], $text);
	}

	/**
	 * Interface name key used to compare names coming from different sources
	 * (e.g. "GigabitEthernet1/0/1", "Gi1/0/1", "Gig 1/0/1" -> "gi1/0/1"; "Module: 1 Port: 2" -> "1/2").
	 */
	public static function portKey($name): string {
		$name = strtolower(trim((string) $name));

		if (preg_match('/module\s*:?\s*(\d+)\s*[,\-]?\s*port\s*:?\s*(\d+)/', $name, $m)) {
			return $m[1].'/'.$m[2];
		}

		$name = preg_replace('/\s+/', '', $name);

		$prefixes = [
			'hundredgigabitethernet' => 'hu', 'hundredgige' => 'hu', 'fortygigabitethernet' => 'fo',
			'twentyfivegigabitethernet' => 'twe', 'twentyfivegige' => 'twe', 'tengigabitethernet' => 'te',
			'tengige' => 'te', 'ten' => 'te', 'gigabitethernet' => 'gi', 'gige' => 'gi', 'gig' => 'gi',
			'fastethernet' => 'fa', 'fas' => 'fa', 'ethernet' => 'eth', 'port-channel' => 'po',
			'portchannel' => 'po', 'interface' => '', 'port' => ''
		];

		foreach ($prefixes as $long => $short) {
			if (strpos($name, $long) === 0) {
				$name = $short.substr($name, strlen($long));
				break;
			}
		}

		return $name;
	}

	/**
	 * Parses a comma/space/newline separated list of SNMP communities.
	 *
	 * @return string[]
	 */
	public static function parseCommunities(string $value, int $max = 8): array {
		$list = [];

		foreach (preg_split('/[\s,;]+/', $value, -1, PREG_SPLIT_NO_EMPTY) as $community) {
			if (strlen($community) <= 64) {
				$list[$community] = $community;
			}
		}

		return array_slice(array_values($list), 0, $max);
	}

	/**
	 * Linux only: reads the ARP cache of the frontend server (useful when it shares the L2 segment).
	 *
	 * @return array  ip => mac
	 */
	public static function localArpTable(): array {
		$table = [];
		$file = '/proc/net/arp';

		if (!@is_readable($file)) {
			return $table;
		}

		foreach (@file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $i => $line) {
			if ($i == 0) {
				continue;
			}

			$cols = preg_split('/\s+/', trim($line));

			// IP address, HW type, Flags, HW address, Mask, Device. Flag 0x2 = complete entry.
			if (count($cols) >= 4 && (hexdec($cols[2]) & 0x2)) {
				$mac = self::normalizeMac($cols[3]);

				if ($mac !== null && self::isIpv4($cols[0])) {
					$table[$cols[0]] = $mac;
				}
			}
		}

		return $table;
	}
}
