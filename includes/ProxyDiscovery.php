<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

use API,
	CWebUser;

/**
 * Scan through a Zabbix proxy using a temporary network discovery rule (Zabbix API, no custom code on the proxy).
 *
 * Lifecycle: start() creates the rule on the selected proxy -> results() is polled by the browser ->
 * stop() deletes the rule (and with it the discovered hosts/services records).
 * Stale rules of the current user are removed by cleanup().
 */
final class ProxyDiscovery {

	public const NAME_PREFIX = 'NetMapper temporary scan';

	// Discovery check types (SVC_* constants of Zabbix).
	private const SVC_SSH = 0;
	private const SVC_HTTP = 4;
	private const SVC_TCP = 8;
	private const SVC_SNMPV1 = 10;
	private const SVC_SNMPV2C = 11;
	private const SVC_ICMPPING = 12;
	private const SVC_SNMPV3 = 13;
	private const SVC_HTTPS = 14;
	private const SVC_TELNET = 15;

	public static function getProxies(): array {
		$proxies = API::Proxy()->get([
			'output' => ['proxyid', 'name'],
			'sortfield' => 'name',
			'preservekeys' => true
		]);

		return $proxies ? array_column($proxies, 'name', 'proxyid') : [];
	}

	/**
	 * @param string $iprange  Zabbix IP range syntax (CIDR, a.b.c.d-e or comma separated list)
	 *
	 * @return string  druleid
	 */
	public static function start(string $proxyid, string $iprange, array $ports, bool $icmp, array $snmp,
			bool $use_snmp): string {
		self::cleanup();

		$dchecks = [];

		if ($icmp) {
			$dchecks[] = ['type' => self::SVC_ICMPPING];
		}

		if ($ports) {
			$dchecks[] = ['type' => self::SVC_TCP, 'ports' => implode(',', $ports)];
		}

		// SNMPv3 secrets are never written into a discovery rule (it would persist them in the database):
		// through a proxy only v1/v2c communities are used.
		if ($use_snmp && $snmp['version'] != 3) {
			foreach ([SnmpProbe::SYSTEM_OIDS['name'], SnmpProbe::SYSTEM_OIDS['descr'], SnmpProbe::SYSTEM_OIDS['objectid']]
					as $oid) {
				foreach ($snmp['communities'] as $community) {
					$dchecks[] = [
						'type' => ($snmp['version'] == 1) ? self::SVC_SNMPV1 : self::SVC_SNMPV2C,
						'ports' => '161',
						'key_' => $oid,
						'snmp_community' => $community
					];
				}
			}
		}

		if (!$dchecks) {
			throw new \RuntimeException(_('Select at least one probe method.'));
		}

		$result = API::DRule()->create([[
			'name' => sprintf('%s %s %s', self::NAME_PREFIX, CWebUser::$data['userid'], date('Y-m-d H:i:s')),
			'iprange' => $iprange,
			'proxyid' => $proxyid,
			'delay' => '1h',
			'status' => 0,
			'dchecks' => $dchecks
		]]);

		if (!$result || empty($result['druleids'])) {
			throw new \RuntimeException(self::apiError(_('Cannot create discovery rule on the proxy.')));
		}

		return (string) reset($result['druleids']);
	}

	/**
	 * @return array  ['results' => [scan results, same format as NetMapperScan], 'diagnostics' => [...]]
	 */
	public static function results(string $druleid): array {
		$drules = API::DRule()->get([
			'output' => ['druleid', 'name', 'proxyid', 'iprange', 'status'],
			'druleids' => [$druleid],
			'selectDChecks' => ['dcheckid', 'type', 'key_', 'ports', 'snmp_community'],
			'editable' => true
		]);

		if (!$drules || strpos($drules[0]['name'], self::NAME_PREFIX) !== 0) {
			throw new \RuntimeException(_('Temporary discovery rule not found.'));
		}

		$dchecks = array_column($drules[0]['dchecks'], null, 'dcheckid');

		$dservices = API::DService()->get([
			'output' => ['dcheckid', 'ip', 'port', 'status', 'value'],
			'druleids' => [$druleid]
		]);

		$hosts = [];
		$system_keys = array_flip(SnmpProbe::SYSTEM_OIDS);

		foreach ($dservices as $dservice) {
			// Discovery service status: 0 = up, 1 = down.
			if ($dservice['status'] != 0 || !array_key_exists($dservice['dcheckid'], $dchecks)) {
				continue;
			}

			$ip = $dservice['ip'];
			$dcheck = $dchecks[$dservice['dcheckid']];

			if (!array_key_exists($ip, $hosts)) {
				$hosts[$ip] = ['ip' => $ip, 'reasons' => [], 'ports' => [], 'snmp' => null];
			}

			switch ($dcheck['type']) {
				case self::SVC_ICMPPING:
					$hosts[$ip]['reasons']['icmp'] = 'icmp';
					break;

				case self::SVC_TCP:
				case self::SVC_SSH:
				case self::SVC_HTTP:
				case self::SVC_HTTPS:
				case self::SVC_TELNET:
					$hosts[$ip]['reasons']['tcp'] = 'tcp';
					$hosts[$ip]['ports'][(int) $dservice['port']] = (int) $dservice['port'];
					break;

				case self::SVC_SNMPV1:
				case self::SVC_SNMPV2C:
				case self::SVC_SNMPV3:
					$hosts[$ip]['reasons']['snmp'] = 'snmp';
					$key = ltrim($dcheck['key_'], '.');

					if ($hosts[$ip]['snmp'] === null) {
						$hosts[$ip]['snmp'] = [
							'version' => [self::SVC_SNMPV1 => 1, self::SVC_SNMPV2C => 2, self::SVC_SNMPV3 => 3][$dcheck['type']],
							'community' => $dcheck['snmp_community'] ?? null,
							'system' => []
						];
					}

					if (array_key_exists($key, $system_keys)) {
						$hosts[$ip]['snmp']['system'][$system_keys[$key]] = $dservice['value'];
					}
					break;
			}
		}

		foreach ($hosts as &$host) {
			$host['reasons'] = array_values($host['reasons']);
			$host['ports'] = array_values($host['ports']);
			sort($host['ports']);

			if ($host['snmp'] !== null) {
				$host['snmp']['system'] = SnmpProbe::formatSystem($host['snmp']['system']);
			}
		}
		unset($host);

		$up = count(array_filter($dservices, static fn($dservice) => $dservice['status'] == 0));

		return [
			'results' => array_values($hosts),
			'diagnostics' => self::diagnostics($drules[0], count($dservices), $up)
		];
	}

	/**
	 * Information to confirm that the scan really runs on the selected proxy.
	 */
	private static function diagnostics(array $drule, int $dservices_total, int $dservices_up): array {
		$proxy = API::Proxy()->get([
			'output' => ['proxyid', 'name', 'operating_mode', 'lastaccess', 'version', 'compatibility', 'state'],
			'proxyids' => [$drule['proxyid']]
		]);
		$proxy = $proxy ? $proxy[0] : null;

		$dhosts = API::DHost()->get([
			'output' => ['dhostid', 'status'],
			'druleids' => [$drule['druleid']]
		]);

		return [
			'druleid' => $drule['druleid'],
			'rule_name' => $drule['name'],
			'iprange' => $drule['iprange'],
			'rule_enabled' => $drule['status'] == 0,
			'dchecks' => count($drule['dchecks']),
			'proxy' => $proxy === null ? null : [
				'proxyid' => $proxy['proxyid'],
				'name' => $proxy['name'],
				// operating_mode: 0 active, 1 passive. state: 0 unknown, 1 offline, 2 online.
				'mode' => $proxy['operating_mode'] == 0 ? 'active' : 'passive',
				'state' => [0 => 'unknown', 1 => 'offline', 2 => 'online'][$proxy['state']] ?? 'unknown',
				'last_seen_sec' => $proxy['lastaccess'] > 0 ? max(0, time() - (int) $proxy['lastaccess']) : null,
				'version' => (int) $proxy['version'],
				// compatibility: 0 undefined, 1 current, 2 outdated, 3 unsupported.
				'compatibility' => [0 => 'undefined', 1 => 'current', 2 => 'outdated', 3 => 'unsupported'][$proxy['compatibility']]
					?? 'undefined'
			],
			'dhosts_total' => count($dhosts),
			'dhosts_up' => count(array_filter($dhosts, static fn($dhost) => $dhost['status'] == 0)),
			'dservices_total' => $dservices_total,
			'dservices_up' => $dservices_up
		];
	}

	public static function stop(string $druleid): void {
		$drules = API::DRule()->get([
			'output' => ['druleid', 'name'],
			'druleids' => [$druleid],
			'editable' => true
		]);

		if ($drules && strpos($drules[0]['name'], self::NAME_PREFIX) === 0) {
			API::DRule()->delete([$druleid]);
		}
	}

	/**
	 * Removes temporary rules of the current user older than 2 hours (e.g. browser closed during a scan).
	 */
	public static function cleanup(): void {
		$drules = API::DRule()->get([
			'output' => ['druleid', 'name'],
			'search' => ['name' => self::NAME_PREFIX.' '.CWebUser::$data['userid'].' '],
			'startSearch' => true,
			'editable' => true
		]);

		$stale = [];
		$limit = time() - 7200;

		foreach ($drules as $drule) {
			$created = strtotime(substr($drule['name'], -19));

			if ($created !== false && $created < $limit) {
				$stale[] = $drule['druleid'];
			}
		}

		if ($stale) {
			API::DRule()->delete($stale);
		}
	}

	private static function apiError(string $default): string {
		if (function_exists('get_and_clear_messages')) {
			$messages = array_column(get_and_clear_messages(), 'message');

			if ($messages) {
				return implode(' ', $messages);
			}
		}

		return $default;
	}
}
