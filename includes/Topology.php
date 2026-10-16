<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Builds the per-port view of a switch from neighbors + MAC table:
 * a port with exactly one learned MAC and without LLDP/CDP neighbor is considered an access port
 * and is linked to the device owning that MAC.
 */
final class Topology {

	/**
	 * @param array    $neighbors  normalized LLDP/CDP neighbors
	 * @param array    $fdb        [['port', 'mac', 'vlan', 'ifindex'?], ...]
	 * @param array    $arp        [['ip', 'mac'], ...]
	 * @param string[] $own_macs   MAC addresses of the switch itself (never counted)
	 *
	 * @return array  ['ports' => [['port', 'mac_count', 'role', 'macs' (<= 8)]], 'access' => [['port', 'mac', 'ip']]]
	 */
	public static function analyze(array $neighbors, array $fdb, array $arp, array $own_macs): array {
		$own = array_flip($own_macs);
		$uplinks = [];

		foreach ($neighbors as $neighbor) {
			$uplinks[Util::portKey($neighbor['local_port'])] = true;

			if (!empty($neighbor['local_ifindex'])) {
				$uplinks['#'.$neighbor['local_ifindex']] = true;
			}
		}

		$mac_to_ip = [];

		foreach ($arp as $entry) {
			$mac_to_ip[$entry['mac']] = $entry['ip'];
		}

		foreach (Util::localArpTable() as $ip => $mac) {
			$mac_to_ip[$mac] = $mac_to_ip[$mac] ?? $ip;
		}

		$ports = [];

		foreach ($fdb as $entry) {
			if (array_key_exists($entry['mac'], $own)) {
				continue;
			}

			$key = Util::portKey($entry['port']);

			if (!array_key_exists($key, $ports)) {
				$ports[$key] = [
					'port' => $entry['port'],
					'ifindex' => $entry['ifindex'] ?? null,
					'macs' => []
				];
			}

			$ports[$key]['macs'][$entry['mac']] = true;
		}

		$result_ports = [];
		$access = [];

		foreach ($ports as $key => $port) {
			$macs = array_keys($port['macs']);
			$is_uplink = array_key_exists($key, $uplinks)
				|| ($port['ifindex'] !== null && array_key_exists('#'.$port['ifindex'], $uplinks));

			if ($is_uplink) {
				$role = 'uplink';
			}
			elseif (count($macs) == 1) {
				$role = 'access';
				$access[] = [
					'port' => $port['port'],
					'mac' => $macs[0],
					'ip' => $mac_to_ip[$macs[0]] ?? ''
				];
			}
			else {
				$role = 'shared';
			}

			$result_ports[] = [
				'port' => $port['port'],
				'mac_count' => count($macs),
				'role' => $role,
				'macs' => array_slice($macs, 0, 8)
			];
		}

		usort($result_ports, static fn($a, $b) => strnatcasecmp($a['port'], $b['port']));

		return ['ports' => $result_ports, 'access' => $access];
	}
}
