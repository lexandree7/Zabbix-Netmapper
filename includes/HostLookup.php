<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

use API;

/**
 * Finds Zabbix hosts by interface IP address (respecting the permissions of the current user).
 */
final class HostLookup {

	/**
	 * @param string[] $ips
	 *
	 * @return array  ip => ['hostid', 'host', 'name', 'status', 'proxyid']
	 */
	public static function byIp(array $ips): array {
		$ips = array_values(array_unique(array_filter($ips, [Util::class, 'isIpv4'])));

		if (!$ips) {
			return [];
		}

		$interfaces = API::HostInterface()->get([
			'output' => ['hostid', 'ip', 'main', 'type'],
			'filter' => ['ip' => $ips]
		]);

		if (!$interfaces) {
			return [];
		}

		$hosts = API::Host()->get([
			'output' => ['hostid', 'host', 'name', 'status', 'proxyid'],
			'hostids' => array_unique(array_column($interfaces, 'hostid')),
			'preservekeys' => true
		]);

		$result = [];

		// Prefer main interfaces when several hosts share an IP.
		usort($interfaces, static fn($a, $b) => $b['main'] <=> $a['main']);

		foreach ($interfaces as $interface) {
			if (!array_key_exists($interface['ip'], $result) && array_key_exists($interface['hostid'], $hosts)) {
				$result[$interface['ip']] = $hosts[$interface['hostid']];
			}
		}

		return $result;
	}
}
