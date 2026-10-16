<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Parsers for CLI output pasted by the user (LLDP / CDP neighbors, MAC address table, ARP table, version).
 * Text only - nothing here talks to the network.
 */
final class CliParsers {

	public const MAX_INPUT = 2097152;

	private const MAC_PATTERN = '/(?<![0-9a-f:.\-])((?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2}|[0-9a-f]{4}[.\-][0-9a-f]{4}[.\-][0-9a-f]{4})(?![0-9a-f:.\-])/i';
	private const IP_PATTERN = '/(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])/';
	private const IFACE_PATTERN = '/^(?:[A-Za-z][A-Za-z\-]*\d+(?:[\/.:]\d+)*|\d+\/\d+(?:\/\d+)?)$/';

	private const KEY_ALIASES = [
		'local_port' => ['localintf', 'localinterface', 'localport', 'localportid', 'localportname', 'localif',
			'localportnum'
		],
		'chassis' => ['chassisid', 'chassis', 'remotechassisid'],
		'port' => ['portid', 'portidoutgoingport', 'remoteportid', 'portinfo', 'remoteport'],
		'port_desc' => ['portdescription', 'portdesc', 'remoteportdescription'],
		'sysname' => ['systemname', 'sysname', 'deviceid', 'remotesystemname', 'neighborsystemname'],
		'sysdesc' => ['systemdescription', 'sysdesc', 'platform'],
		'mgmt' => ['managementaddress', 'managementaddresses', 'ipv4managementaddress', 'managementip',
			'mgmtaddress', 'ipaddress', 'ip', 'address', 'ipv4address', 'entryaddresses', 'mgmtip'
		],
		'caps' => ['systemcapabilities', 'enabledcapabilities', 'capabilities', 'systemcapabilitiesenabled',
			'enabledcaps', 'syscapenabled'
		]
	];

	private const IGNORED_PORT_TOKENS = ['cpu', 'router', 'drop', 'switch', 'self', 'local', 'sup-eth1', 'vlan'];

	public static function isError(string $output): bool {
		return (bool) preg_match('/%\s*(invalid|incomplete|unknown|ambiguous)|unknown command|unrecognized command|'
			.'syntax error|bad command|expected end|no such command|invalid input|error:/i', $output
		);
	}

	/**
	 * @return array  [['protocol', 'local_port', 'remote_chassis', 'remote_port', 'remote_port_desc',
	 *                  'remote_sysname', 'remote_ip', 'remote_sysdesc', 'remote_caps'], ...]
	 */
	public static function parseNeighbors(string $text, string $vendor, string $protocol = 'lldp'): array {
		$text = self::prepare($text);

		if ($text === '' || self::isError($text) && !preg_match('/chassis|device id|neighbor/i', $text)) {
			return [];
		}

		if ($vendor === 'mikrotik' || preg_match('/\binterface-name=|\bidentity=/', $text)) {
			return self::parseMikrotikNeighbors($text);
		}

		$records = self::parseNeighborBlocks($text, $protocol);

		if (!$records) {
			$records = self::parseNeighborTable($text, $protocol);
		}

		return $records;
	}

	/**
	 * @return array  [['port' => .., 'mac' => .., 'vlan' => ..], ...]
	 */
	public static function parseMacTable(string $text, string $vendor): array {
		$text = self::prepare($text);
		$entries = [];

		if ($vendor === 'mikrotik' || preg_match('/\bon-interface=|\bmac-address=/', $text)) {
			foreach (self::mikrotikRecords($text) as $record) {
				$fields = $record['fields'];

				if (strpos($record['flags'], 'L') !== false || ($fields['local'] ?? 'no') === 'yes') {
					continue;
				}

				$mac = Util::normalizeMac($fields['mac-address'] ?? '');
				$port = $fields['on-interface'] ?? ($fields['interface'] ?? ($fields['port'] ?? ''));

				if ($mac !== null && $port !== '') {
					$entries[$port.'|'.$mac] = ['port' => $port, 'mac' => $mac, 'vlan' => $fields['vid'] ?? ''];
				}
			}

			return array_values($entries);
		}

		$column = null;

		foreach (explode("\n", $text) as $line) {
			if (trim($line) === '') {
				continue;
			}

			if (!preg_match(self::MAC_PATTERN, $line, $mac_match, PREG_OFFSET_CAPTURE)) {
				// Header line: remember where the port column starts.
				if (preg_match('/mac/i', $line)
						&& preg_match('/\b(Learned-From|Ports?|Logical interface|Interface|Intf|Destination)\b/i', $line,
							$h, PREG_OFFSET_CAPTURE)) {
					$column = $h[1][1];
				}

				continue;
			}

			$mac = Util::normalizeMac($mac_match[1][0]);

			if ($mac === null || preg_match('/\b(self|cpu|management|mgmt)\b/i', $line)) {
				continue;
			}

			$port = null;
			preg_match_all('/\S+/', $line, $tokens, PREG_OFFSET_CAPTURE);

			if ($column !== null) {
				foreach ($tokens[0] as [$token, $offset]) {
					if ($offset + strlen($token) > $column - 1 && $offset <= $column + 2 && $token !== $mac_match[1][0]) {
						$port = $token;
						break;
					}
				}
			}

			if ($port === null || !self::isInterfaceToken($port, true)) {
				$port = null;

				foreach (array_reverse($tokens[0]) as [$token]) {
					if ($token !== $mac_match[1][0] && self::isInterfaceToken($token, false)) {
						$port = $token;
						break;
					}
				}
			}

			if ($port === null) {
				continue;
			}

			$vlan = '';

			if (preg_match('/^\s*(\d{1,4})\s/', $line, $v)) {
				$vlan = $v[1];
			}

			$entries[$port.'|'.$mac] = ['port' => rtrim($port, ','), 'mac' => $mac, 'vlan' => $vlan];
		}

		return array_values($entries);
	}

	/**
	 * @return array  [['ip' => .., 'mac' => ..], ...]
	 */
	public static function parseArp(string $text): array {
		$entries = [];

		foreach (explode("\n", self::prepare($text)) as $line) {
			if (preg_match(self::IP_PATTERN, $line, $ip) && preg_match(self::MAC_PATTERN, $line, $mac)) {
				$mac = Util::normalizeMac($mac[1]);

				if ($mac !== null && Util::isIpv4($ip[1])) {
					$entries[$ip[1]] = ['ip' => $ip[1], 'mac' => $mac];
				}
			}
		}

		return array_values($entries);
	}

	/**
	 * @return array  ['hostname' => string, 'macs' => string[], 'text' => string]
	 */
	public static function parseVersion(string $text): array {
		$text = self::prepare($text);
		$hostname = '';

		if (preg_match('/^(\S+)\s+uptime is/m', $text, $m)) {
			$hostname = $m[1];
		}
		elseif (preg_match('/^\s*(?:system name|sysname|hostname|identity|name)\s*[:.=]+\s*(\S.*)$/mi', $text, $m)) {
			$hostname = trim($m[1], " \t\"");
		}

		// Base / system / management MAC (e.g. Cisco "Base ethernet MAC Address", HiOS "MAC address (management)").
		$macs = [];

		foreach (explode("
", $text) as $line) {
			if (preg_match('/mac|chassis|bridge address/i', $line) && preg_match(self::MAC_PATTERN, $line, $m)) {
				$mac = Util::normalizeMac($m[1]);

				if ($mac !== null) {
					$macs[$mac] = $mac;
				}
			}
		}

		return ['hostname' => Util::text($hostname, 128), 'macs' => array_values($macs), 'text' => Util::text($text, 8192)];
	}

	private static function prepare(string $text): string {
		if (strlen($text) > self::MAX_INPUT) {
			$text = substr($text, 0, self::MAX_INPUT);
		}

		$text = Util::stripAnsi($text);

		// Remove pager leftovers.
		$text = preg_replace('/\s*-{1,4}\s*more\s*-{1,4}\s*|<--- More --->|\(more\)|Press any key to continue\.*/i', "\n",
			$text
		);

		return mb_check_encoding($text, 'UTF-8') ? $text : mb_convert_encoding($text, 'UTF-8', 'ISO-8859-1');
	}

	private static function isInterfaceToken(string $token, bool $allow_numeric): bool {
		$token = rtrim($token, ',');

		if (in_array(strtolower($token), self::IGNORED_PORT_TOKENS, true) || Util::normalizeMac($token) !== null
				|| Util::isIpv4($token)) {
			return false;
		}

		if (preg_match('/^(dynamic|static|learned|secure|permanent|igmp|yes|no|all|config|forward|true|false)$/i',
				$token)) {
			return false;
		}

		if ($allow_numeric && preg_match('/^\d{1,3}$/', $token)) {
			return true;
		}

		return (bool) preg_match(self::IFACE_PATTERN, $token);
	}

	private static function normalizeKey(string $key): ?string {
		$key = preg_replace('/[^a-z0-9]/', '', strtolower($key));

		foreach (self::KEY_ALIASES as $field => $aliases) {
			if (in_array($key, $aliases, true)) {
				return $field;
			}
		}

		return null;
	}

	private static function parseNeighborBlocks(string $text, string $protocol): array {
		$records = [];
		$current = [];
		$section_local = null;

		$flush = static function () use (&$records, &$current, $protocol) {
			$record = self::finalizeNeighbor($current, $protocol);

			if ($record !== null) {
				$records[] = $record;
			}

			$current = [];
		};

		foreach (explode("\n", $text) as $line) {
			$trimmed = trim($line);

			if ($trimmed === '') {
				continue;
			}

			if (preg_match('/^-{4,}|^={4,}/', $trimmed)) {
				$flush();
				continue;
			}

			// Hirschmann: "Remote Data, 1/1 - #1".
			if (preg_match('/^Remote Data,\s*(\S+?)\s*(?:-|$)/i', $trimmed, $m)) {
				$flush();
				$current['local_port'] = $m[1];
				continue;
			}

			// Huawei: "GigabitEthernet0/0/1 has 1 neighbor(s):"; Comware: "... of port 1[GigabitEthernet1/0/1]:".
			if (preg_match('/^(\S+)\s+has\s+\d+\s+neighbou?r/i', $trimmed, $m)
					|| preg_match('/neighbou?r-information of port \d+\[([^\]]+)\]/i', $trimmed, $m)) {
				$flush();
				$section_local = $m[1];
				continue;
			}

			if (preg_match('/^Neighbou?r(?: index)?\s*[:#]?\s*\d+/i', $trimmed)) {
				$flush();

				if ($section_local !== null) {
					$current['local_port'] = $section_local;
				}

				continue;
			}

			// Cisco CDP combined lines.
			if (preg_match('/^Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(.+)$/i', $trimmed, $m)) {
				$current['local_port'] = trim($m[1]);
				$current['port'] = trim($m[2]);
				continue;
			}

			if (preg_match('/^Platform:\s*([^,]+),\s*Capabilities:\s*(.*)$/i', $trimmed, $m)) {
				$current['sysdesc'] = trim($m[1]);
				$current['caps'] = trim($m[2]);
				continue;
			}

			if (!preg_match('/^([A-Za-z][\w \-\/\(\)#]*?)\s*(?:\.{2,}\s*|:\s*|=\s*)(.*)$/', $trimmed, $m)) {
				continue;
			}

			$field = self::normalizeKey($m[1]);
			$value = trim($m[2], " \t\"");

			if ($field === null) {
				continue;
			}

			if ($field === 'mgmt') {
				if (preg_match(self::IP_PATTERN, $value, $ip) && !isset($current['mgmt'])) {
					$current['mgmt'] = $ip[1];
				}

				continue;
			}

			if ($value === '') {
				continue;
			}

			// New neighbor starts when a unique field repeats.
			if (array_key_exists($field, $current) && in_array($field, ['local_port', 'chassis', 'sysname'], true)
					&& ($field !== 'sysname' || isset($current['chassis']) || isset($current['port']))) {
				$flush();

				if ($field !== 'local_port' && $section_local !== null) {
					$current['local_port'] = $section_local;
				}
			}

			$current[$field] = $value;
		}

		$flush();

		return $records;
	}

	/**
	 * Fallback for tabular output, e.g. "show lldp neighbors" (Cisco/Juniper).
	 */
	private static function parseNeighborTable(string $text, string $protocol): array {
		$lines = explode("\n", $text);
		$columns = null;
		$records = [];

		foreach ($lines as $line) {
			if ($columns === null) {
				if (preg_match('/local\s*(intf|interface|port)/i', $line)
						&& preg_match('/(device id|system name|chassis id|port id|port info)/i', $line)) {
					$columns = [];
					$names = [
						'sysname' => '/device id|system name/i', 'local_port' => '/local\s*(intf|interface|port)/i',
						'chassis' => '/chassis id/i', 'port' => '/port id|port info/i'
					];

					foreach ($names as $field => $pattern) {
						if (preg_match($pattern, $line, $m, PREG_OFFSET_CAPTURE)) {
							$columns[$field] = $m[0][1];
						}
					}

					asort($columns);
				}

				continue;
			}

			if (trim($line) === '' || preg_match('/^total|capability codes/i', trim($line))) {
				continue;
			}

			$record = [];
			$fields = array_keys($columns);
			$starts = array_values($columns);

			foreach ($fields as $i => $field) {
				$start = $starts[$i];
				$end = $starts[$i + 1] ?? null;
				$value = $end !== null ? substr($line, $start, $end - $start) : substr($line, $start);
				$value = trim((string) $value);

				// Columns not listed (hold-time, capability) may sit between two known ones: keep the first chunk.
				$record[$field] = preg_split('/\s{2,}/', $value)[0];
			}

			$neighbor = self::finalizeNeighbor($record, $protocol);

			if ($neighbor !== null) {
				$records[] = $neighbor;
			}
		}

		return $records;
	}

	private static function finalizeNeighbor(array $record, string $protocol): ?array {
		if (empty($record['local_port'])
				|| (empty($record['chassis']) && empty($record['sysname']) && empty($record['mgmt']))) {
			return null;
		}

		$chassis = $record['chassis'] ?? '';
		$chassis_mac = Util::normalizeMac($chassis);

		return [
			'protocol' => $protocol,
			'local_port' => Util::text($record['local_port'], 64),
			'remote_chassis' => $chassis_mac ?? Util::text($chassis, 128),
			'remote_port' => Util::text($record['port'] ?? '', 128),
			'remote_port_desc' => Util::text($record['port_desc'] ?? '', 255),
			'remote_sysname' => Util::text($record['sysname'] ?? '', 255),
			'remote_ip' => $record['mgmt'] ?? '',
			'remote_sysdesc' => Util::text($record['sysdesc'] ?? '', 512),
			'remote_caps' => Util::text($record['caps'] ?? '', 128)
		];
	}

	/**
	 * RouterOS "print detail" output: records start with an index number, fields are key=value.
	 *
	 * @return array  [['flags' => string, 'fields' => array], ...]
	 */
	private static function mikrotikRecords(string $text): array {
		$records = [];
		$current = null;

		foreach (explode("\n", $text) as $line) {
			if (preg_match('/^\s*(\d+)\s+([A-Z ]*?)\s*(?=[a-z][\w\-]*=|;;;|$)(.*)$/', $line, $m)) {
				if ($current !== null) {
					$records[] = $current;
				}

				$current = ['flags' => str_replace(' ', '', $m[2]), 'raw' => $m[3]];
			}
			elseif ($current !== null) {
				$current['raw'] .= ' '.trim($line);
			}
		}

		if ($current !== null) {
			$records[] = $current;
		}

		foreach ($records as &$record) {
			preg_match_all('/([a-z][\w\-]*)=("(?:[^"\\\\]|\\\\.)*"|\S*)/', $record['raw'], $pairs, PREG_SET_ORDER);
			$record['fields'] = [];

			foreach ($pairs as $pair) {
				$record['fields'][$pair[1]] = trim($pair[2], '"');
			}

			unset($record['raw']);
		}
		unset($record);

		return $records;
	}

	private static function parseMikrotikNeighbors(string $text): array {
		$neighbors = [];

		foreach (self::mikrotikRecords($text) as $record) {
			$f = $record['fields'];
			$local = explode(',', $f['interface'] ?? '')[0];
			$ip = $f['address4'] ?? ($f['address'] ?? '');

			if ($local === '') {
				continue;
			}

			$neighbors[] = [
				'protocol' => strtolower(explode(',', $f['discovered-by'] ?? 'lldp')[0]) ?: 'lldp',
				'local_port' => Util::text($local, 64),
				'remote_chassis' => Util::normalizeMac($f['mac-address'] ?? '') ?? '',
				'remote_port' => Util::text($f['interface-name'] ?? '', 128),
				'remote_port_desc' => '',
				'remote_sysname' => Util::text($f['identity'] ?? '', 255),
				'remote_ip' => Util::isIpv4($ip) ? $ip : '',
				'remote_sysdesc' => Util::text(trim(($f['platform'] ?? '').' '.($f['board'] ?? '').' '
					.($f['version'] ?? '').' '.($f['system-description'] ?? '')), 512
				),
				'remote_caps' => Util::text($f['system-caps-enabled'] ?? ($f['system-caps'] ?? ''), 128)
			];
		}

		return $neighbors;
	}
}
