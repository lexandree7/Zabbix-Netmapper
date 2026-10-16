<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

use API,
	CWebUser;

/**
 * SNMP collection through a proxy using temporary native monitoring: a host monitored by the selected proxy with
 * "SNMP agent" items walk[<oid>]. The values are read back from the history and the host is deleted afterwards.
 *
 * The community is stored in a secret user macro of the temporary host (SNMPv1/v2c only).
 */
final class ProxyWalk {

	public const HOST_PREFIX = 'netmapper-tmp-';
	public const GROUP_NAME = 'NetMapper temporary';
	public const MACRO = '{$NETMAPPER_COMMUNITY}';
	public const STALE_AFTER = 7200;

	/**
	 * Subtrees collected from a switch (one walk[] item each).
	 */
	public const SUBTREES = [
		'1.3.6.1.2.1.1', '1.3.6.1.2.1.2.2.1.2', '1.3.6.1.2.1.2.2.1.6', '1.3.6.1.2.1.31.1.1.1.1',
		'1.0.8802.1.1.2.1.3', '1.0.8802.1.1.2.1.4', '1.3.6.1.4.1.9.9.23.1.2.1.1', '1.3.6.1.2.1.17.1',
		'1.3.6.1.2.1.17.7.1.2.2.1', '1.3.6.1.2.1.17.4.3.1', '1.3.6.1.2.1.4.22.1.2', '1.3.6.1.2.1.4.35.1.4'
	];

	/**
	 * @return string  hostid of the temporary host
	 */
	public static function start(string $proxyid, string $ip, int $version, string $community): string {
		if (!Util::isIpv4($ip)) {
			throw new \InvalidArgumentException(_('Invalid IP address.'));
		}

		self::cleanup();

		$group = API::HostGroup()->get(['output' => ['groupid'], 'filter' => ['name' => self::GROUP_NAME]]);

		if (!$group) {
			if (CWebUser::getType() != USER_TYPE_SUPER_ADMIN) {
				throw new \RuntimeException(sprintf(_('Host group "%1$s" does not exist and only Super admin users can '
					.'create it. Ask a Super admin to create it and grant your user group read-write access.'),
					self::GROUP_NAME
				));
			}

			$created = API::HostGroup()->create([['name' => self::GROUP_NAME]]);

			if (!$created) {
				throw new \RuntimeException(ProxyScript::apiError(_('Cannot create host group.')));
			}

			$groupid = reset($created['groupids']);
		}
		else {
			$groupid = $group[0]['groupid'];
		}

		$result = API::Host()->create([[
			'host' => self::HOST_PREFIX.CWebUser::$data['userid'].'-'.time().'-'.mt_rand(100, 999),
			'name' => sprintf('NetMapper temporary %s', $ip),
			'description' => 'Temporary host of the Network mapper module. Deleted automatically.',
			'monitored_by' => ZBX_MONITORED_BY_PROXY,
			'proxyid' => $proxyid,
			'groups' => [['groupid' => $groupid]],
			'interfaces' => [[
				'type' => INTERFACE_TYPE_SNMP, 'main' => INTERFACE_PRIMARY, 'useip' => INTERFACE_USE_IP, 'ip' => $ip,
				'dns' => '', 'port' => '161',
				'details' => ['version' => $version, 'bulk' => SNMP_BULK_ENABLED, 'community' => self::MACRO]
			]],
			'macros' => [['macro' => self::MACRO, 'value' => $community, 'type' => ZBX_MACRO_TYPE_SECRET]]
		]]);

		if (!$result) {
			throw new \RuntimeException(ProxyScript::apiError(_('Cannot create temporary host.')));
		}

		$hostid = (string) reset($result['hostids']);

		try {
			$interfaces = API::HostInterface()->get(['output' => ['interfaceid'], 'hostids' => [$hostid]]);
			$items = [];

			foreach (self::SUBTREES as $i => $oid) {
				$items[] = [
					'hostid' => $hostid,
					'interfaceid' => $interfaces[0]['interfaceid'],
					'name' => 'walk '.$oid,
					'key_' => 'netmapper.walk.'.$i,
					'type' => ITEM_TYPE_SNMP,
					'snmp_oid' => 'walk['.$oid.']',
					'value_type' => ITEM_VALUE_TYPE_TEXT,
					'delay' => '30s',
					'history' => '1h'
				];
			}

			if (!API::Item()->create($items)) {
				throw new \RuntimeException(ProxyScript::apiError(_('Cannot create temporary items.')));
			}
		}
		catch (\Throwable $e) {
			self::stop($hostid);

			throw $e;
		}

		return $hostid;
	}

	/**
	 * @return array  ['done' => bool, 'collected' => int, 'failed' => int, 'total' => int, 'values' => [...],
	 *                 'errors' => string[]]
	 */
	public static function poll(string $hostid): array {
		self::assertOwned($hostid);

		$items = API::Item()->get([
			'output' => ['itemid', 'key_', 'state', 'error', 'snmp_oid'],
			'hostids' => [$hostid]
		]);

		$history = $items ? API::History()->get([
			'output' => 'extend',
			'history' => ITEM_VALUE_TYPE_TEXT,
			'itemids' => array_column($items, 'itemid'),
			'sortfield' => 'clock',
			'sortorder' => 'DESC',
			'limit' => count($items) * 3
		]) : [];

		$latest = [];

		foreach ($history as $row) {
			$latest += [$row['itemid'] => $row['value']];
		}

		$values = [];
		$errors = [];
		$collected = 0;
		$failed = 0;

		foreach ($items as $item) {
			if (array_key_exists($item['itemid'], $latest)) {
				$values += self::parseWalk($latest[$item['itemid']]);
				$collected++;
			}
			elseif ($item['state'] == ITEM_STATE_NOTSUPPORTED && $item['error'] !== '') {
				$failed++;
				$errors[$item['snmp_oid']] = $item['error'];
			}
		}

		$total = count($items);

		return [
			'done' => $total > 0 && $collected + $failed >= $total,
			'collected' => $collected,
			'failed' => $failed,
			'total' => $total,
			'values' => $values,
			'errors' => array_values(array_unique($errors))
		];
	}

	public static function stop(string $hostid): void {
		$hosts = API::Host()->get(['output' => ['hostid', 'host'], 'hostids' => [$hostid], 'editable' => true]);

		if ($hosts && strpos($hosts[0]['host'], self::HOST_PREFIX) === 0) {
			API::Host()->delete([$hostid]);
		}
	}

	/**
	 * Removes temporary hosts of the current user older than STALE_AFTER seconds.
	 */
	public static function cleanup(): void {
		$hosts = API::Host()->get([
			'output' => ['hostid', 'host'],
			'search' => ['host' => self::HOST_PREFIX.CWebUser::$data['userid'].'-'],
			'startSearch' => true,
			'editable' => true
		]);
		$stale = [];

		foreach ($hosts as $host) {
			$parts = explode('-', $host['host']);

			if (count($parts) >= 4 && (int) $parts[3] < time() - self::STALE_AFTER) {
				$stale[] = $host['hostid'];
			}
		}

		if ($stale) {
			API::Host()->delete($stale);
		}
	}

	private static function assertOwned(string $hostid): void {
		$hosts = API::Host()->get(['output' => ['host'], 'hostids' => [$hostid]]);

		if (!$hosts || strpos($hosts[0]['host'], self::HOST_PREFIX.CWebUser::$data['userid'].'-') !== 0) {
			throw new \RuntimeException(_('Temporary host not found.'));
		}
	}

	/**
	 * Parses the output of walk[]: one "OID = TYPE: value" per line (values with line breaks continue on the next
	 * lines). Returns oid (no leading dot) => value, with the types the SNMP session API uses (int, raw string).
	 */
	public static function parseWalk(string $text): array {
		$values = [];
		$oid = null;
		$raw = '';

		$flush = static function () use (&$values, &$oid, &$raw) {
			if ($oid !== null) {
				$value = self::convert($raw);

				if ($value !== null) {
					$values[$oid] = $value;
				}
			}

			$oid = null;
			$raw = '';
		};

		foreach (preg_split('/\r?\n/', $text) as $line) {
			if (preg_match('/^\s*\.?(\d+(?:\.\d+)+)\s*=\s*(.*)$/', $line, $m)) {
				$flush();
				$oid = $m[1];
				$raw = $m[2];
			}
			elseif ($oid !== null) {
				$raw .= "\n".$line;
			}
		}

		$flush();

		return $values;
	}

	private static function convert(string $raw) {
		$raw = rtrim($raw);

		if (!preg_match('/^([A-Za-z0-9\-]+):\s?(.*)$/s', $raw, $m)) {
			return ($raw === '""' || $raw === '') ? '' : null;
		}

		[$type, $value] = [$m[1], $m[2]];

		switch ($type) {
			case 'Hex-STRING':
				$hex = preg_replace('/[^0-9a-fA-F]/', '', $value);

				return strlen($hex) % 2 == 0 ? (string) hex2bin($hex) : $value;

			case 'STRING':
				$value = trim($value);

				return (strlen($value) >= 2 && $value[0] === '"' && substr($value, -1) === '"')
					? substr($value, 1, -1)
					: $value;

			case 'INTEGER':
			case 'Gauge32':
			case 'Counter32':
			case 'Counter64':
			case 'UInteger32':
			case 'Unsigned32':
			case 'Timeticks':
				return preg_match('/\(?(-?\d+)\)?/', $value, $n) ? (int) $n[1] : null;

			case 'OID':
				return ltrim(trim($value), '.');

			case 'IpAddress':
				return trim($value);

			default:
				return null;
		}
	}
}
