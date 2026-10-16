<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Read-only SNMP collection of LLDP / CDP neighbors, forwarding database (MAC table) and ARP table.
 */
final class NeighborCollector {

	private const IF_NAME = '1.3.6.1.2.1.31.1.1.1.1';
	private const IF_DESCR = '1.3.6.1.2.1.2.2.1.2';
	private const IF_PHYS_ADDRESS = '1.3.6.1.2.1.2.2.1.6';

	private const LLDP_LOC_CHASSIS_SUBTYPE = '1.0.8802.1.1.2.1.3.1.0';
	private const LLDP_LOC_CHASSIS_ID = '1.0.8802.1.1.2.1.3.2.0';
	private const LLDP_LOC_SYSNAME = '1.0.8802.1.1.2.1.3.3.0';
	private const SYS_NAME = '1.3.6.1.2.1.1.5.0';
	private const DOT1D_BASE_BRIDGE_ADDRESS = '1.3.6.1.2.1.17.1.1.0';
	private const LLDP_LOC_PORT_ID_SUBTYPE = '1.0.8802.1.1.2.1.3.7.1.2';
	private const LLDP_LOC_PORT_ID = '1.0.8802.1.1.2.1.3.7.1.3';
	private const LLDP_LOC_PORT_DESC = '1.0.8802.1.1.2.1.3.7.1.4';
	private const LLDP_REM = '1.0.8802.1.1.2.1.4.1.1';
	private const LLDP_REM_MAN_ADDR_IF_SUBTYPE = '1.0.8802.1.1.2.1.4.2.1.3';

	private const CDP_CACHE = '1.3.6.1.4.1.9.9.23.1.2.1.1';

	private const DOT1D_BASE_PORT_IFINDEX = '1.3.6.1.2.1.17.1.4.1.2';
	private const DOT1D_TP_FDB_PORT = '1.3.6.1.2.1.17.4.3.1.2';
	private const DOT1D_TP_FDB_STATUS = '1.3.6.1.2.1.17.4.3.1.3';
	private const DOT1Q_TP_FDB_PORT = '1.3.6.1.2.1.17.7.1.2.2.1.2';
	private const DOT1Q_TP_FDB_STATUS = '1.3.6.1.2.1.17.7.1.2.2.1.3';
	private const CISCO_VTP_VLAN_STATE = '1.3.6.1.4.1.9.9.46.1.3.1.1.2';

	private const IP_NET_TO_MEDIA_PHYS = '1.3.6.1.2.1.4.22.1.2';
	private const IP_NET_TO_PHYSICAL_PHYS = '1.3.6.1.2.1.4.35.1.4';

	// dot1dTpFdbStatus / dot1qTpFdbStatus: 3 = learned, 4 = self, 5 = mgmt.
	private const FDB_STATUS_SELF = [4, 5];

	private SnmpSession $session;
	private ?string $vendor;
	private array $log = [];
	private array $if_names = [];
	private array $loc_subtype = [];
	private array $loc_id = [];
	private array $loc_desc = [];

	public function __construct(SnmpSession $session, ?string $vendor) {
		$this->session = $session;
		$this->vendor = $vendor;
	}

	public function getLog(): array {
		return $this->log;
	}

	/**
	 * @return array  ['neighbors' => [], 'fdb' => [], 'arp' => [], 'own_macs' => []]
	 */
	public function collect(bool $with_fdb = true): array {
		$this->loadInterfaces();

		$local = $this->localIdentity();
		$neighbors = $this->lldp();

		if ($this->vendor === null || in_array($this->vendor, ['cisco', 'rockwell'], true)) {
			$neighbors = array_merge($neighbors, $this->cdp());
		}

		$fdb = $with_fdb ? $this->fdb() : [];
		$arp = $this->arp();

		$own_macs = [];

		try {
			foreach ($this->session->walk(self::IF_PHYS_ADDRESS, 4000) as $value) {
				$mac = Util::macFromSnmp($value);

				if ($mac !== null) {
					$own_macs[$mac] = $mac;
				}
			}
		}
		catch (SnmpTimeoutException $e) {
		}

		foreach ([$local['bridge_mac'], Util::normalizeMac($local['chassis_id'])] as $mac) {
			if ($mac !== null) {
				$own_macs[$mac] = $mac;
			}
		}

		return [
			'neighbors' => $neighbors,
			'fdb' => $fdb,
			'arp' => $arp,
			'own_macs' => array_values($own_macs),
			'local' => $local
		];
	}

	private function loadInterfaces(): void {
		try {
			$this->if_names = array_map([Util::class, 'text'], $this->session->walkIndex(self::IF_NAME, 8000));
		}
		catch (SnmpTimeoutException $e) {
			$this->if_names = [];
		}

		if (!$this->if_names || !array_filter($this->if_names)) {
			$this->if_names = array_map([Util::class, 'text'], $this->session->walkIndex(self::IF_DESCR, 8000));
		}

		$this->log[] = sprintf('SNMP: %d interfaces.', count($this->if_names));
	}

	private function ifName($if_index): string {
		return $this->if_names[(string) $if_index] ?? ('ifIndex '.$if_index);
	}

	/**
	 * Identity of the queried device as its neighbors see it through LLDP: chassis ID, LLDP system name and the
	 * port IDs it advertises (e.g. "port-008" for ifName "Fa0/8"). Used by the map to avoid duplicated devices.
	 *
	 * @return array  ['chassis_id', 'sysname', 'lldp_sysname', 'bridge_mac', 'port_ids' => [['name', 'id', 'desc']]]
	 */
	private function localIdentity(): array {
		$local = ['chassis_id' => '', 'sysname' => '', 'lldp_sysname' => '', 'bridge_mac' => null, 'port_ids' => []];

		try {
			$values = $this->session->get([self::LLDP_LOC_CHASSIS_SUBTYPE, self::LLDP_LOC_CHASSIS_ID,
				self::LLDP_LOC_SYSNAME, self::SYS_NAME, self::DOT1D_BASE_BRIDGE_ADDRESS
			]);

			if ($values[self::LLDP_LOC_CHASSIS_ID] !== null) {
				$local['chassis_id'] = ((int) $values[self::LLDP_LOC_CHASSIS_SUBTYPE] == 4)
					? (Util::macFromSnmp($values[self::LLDP_LOC_CHASSIS_ID]) ?? '')
					: Util::text($values[self::LLDP_LOC_CHASSIS_ID], 128);
			}

			$local['lldp_sysname'] = Util::text($values[self::LLDP_LOC_SYSNAME], 255);
			$local['sysname'] = Util::text($values[self::SYS_NAME], 255);
			$local['bridge_mac'] = Util::macFromSnmp($values[self::DOT1D_BASE_BRIDGE_ADDRESS]);

			$this->loc_subtype = $this->session->walkIndex(self::LLDP_LOC_PORT_ID_SUBTYPE, 2000);
			$this->loc_id = $this->session->walkIndex(self::LLDP_LOC_PORT_ID, 2000);
			$this->loc_desc = $this->session->walkIndex(self::LLDP_LOC_PORT_DESC, 2000);
		}
		catch (SnmpTimeoutException $e) {
			return $local;
		}

		foreach ($this->loc_id as $num => $value) {
			$name = $this->if_names[$num] ?? '';
			$id = ((int) ($this->loc_subtype[$num] ?? 0) == 3)
				? (Util::macFromSnmp($value) ?? '')
				: Util::text($value, 64);
			$desc = Util::text($this->loc_desc[$num] ?? '', 128);

			if ($name === '') {
				$name = $desc !== '' ? $desc : $id;
			}

			if ($name !== '' && ($id !== $name || ($desc !== '' && $desc !== $name))) {
				$local['port_ids'][] = ['name' => $name, 'id' => $id, 'desc' => $desc];
			}
		}

		$this->log[] = sprintf('SNMP LLDP local: chassis %s, name "%s", %d port IDs.', $local['chassis_id'] ?: '-',
			$local['lldp_sysname'] ?: $local['sysname'], count($local['port_ids'])
		);

		return $local;
	}

	private function lldp(): array {
		try {
			$columns = [];

			// 4 chassis subtype, 5 chassis id, 6 port subtype, 7 port id, 8 port desc, 9 sys name, 10 sys desc, 12 caps.
			foreach ([4, 5, 6, 7, 8, 9, 10, 12] as $column) {
				$columns[$column] = $this->session->walkIndex(self::LLDP_REM.'.'.$column, 4000);
			}
		}
		catch (SnmpTimeoutException $e) {
			$this->log[] = 'SNMP LLDP-MIB: '.$e->getMessage();

			return [];
		}

		if (!$columns[5] && !$columns[9]) {
			$this->log[] = 'SNMP LLDP-MIB: no neighbors (or LLDP-MIB not supported).';

			return [];
		}

		$loc_subtype = $this->loc_subtype;
		$loc_id = $this->loc_id;
		$loc_desc = $this->loc_desc;

		// lldpRemManAddrTable index: timeMark.localPortNum.remIndex.addrSubtype.addrLen.addr...
		$management = [];

		foreach ($this->session->walkIndex(self::LLDP_REM_MAN_ADDR_IF_SUBTYPE, 4000) as $index => $value) {
			$parts = explode('.', $index);

			if (count($parts) >= 9 && $parts[3] == 1 && $parts[4] == 4) {
				$key = $parts[0].'.'.$parts[1].'.'.$parts[2];
				$management[$key] = $management[$key] ?? implode('.', array_slice($parts, 5, 4));
			}
		}

		$neighbors = [];

		foreach (array_unique(array_merge(array_keys($columns[5]), array_keys($columns[9]))) as $index) {
			$parts = explode('.', $index);

			if (count($parts) < 3) {
				continue;
			}

			$local_num = $parts[1];
			$chassis_subtype = (int) ($columns[4][$index] ?? 0);
			$port_subtype = (int) ($columns[6][$index] ?? 0);

			$chassis = ($chassis_subtype == 4)
				? (Util::macFromSnmp($columns[5][$index] ?? '') ?? '')
				: Util::text($columns[5][$index] ?? '', 128);

			$port = ($port_subtype == 3)
				? (Util::macFromSnmp($columns[7][$index] ?? '') ?? '')
				: Util::text($columns[7][$index] ?? '', 128);

			$neighbors[] = [
				'protocol' => 'lldp',
				'local_port' => $this->lldpLocalPort($local_num, $loc_subtype, $loc_id, $loc_desc),
				'local_ifindex' => array_key_exists($local_num, $this->if_names) ? (int) $local_num : null,
				'remote_chassis' => $chassis,
				'remote_port' => $port,
				'remote_port_desc' => Util::text($columns[8][$index] ?? '', 255),
				'remote_sysname' => Util::text($columns[9][$index] ?? '', 255),
				'remote_ip' => $management[$parts[0].'.'.$parts[1].'.'.$parts[2]] ?? '',
				'remote_sysdesc' => Util::text($columns[10][$index] ?? '', 512),
				'remote_caps' => self::lldpCaps($columns[12][$index] ?? null)
			];
		}

		$this->log[] = sprintf('SNMP LLDP-MIB: %d neighbors.', count($neighbors));

		return $neighbors;
	}

	private function lldpLocalPort(string $num, array $subtype, array $id, array $desc): string {
		// interfaceName(5) / interfaceAlias(1) port IDs are directly usable.
		if (in_array((int) ($subtype[$num] ?? 0), [1, 5], true) && trim((string) ($id[$num] ?? '')) !== '') {
			return Util::text($id[$num], 64);
		}

		if (array_key_exists($num, $this->if_names)) {
			return $this->if_names[$num];
		}

		foreach ([$desc[$num] ?? '', $id[$num] ?? ''] as $value) {
			$value = Util::text($value, 64);

			if ($value !== '') {
				return $value;
			}
		}

		return 'port '.$num;
	}

	/**
	 * LldpSystemCapabilitiesMap BITS: other(0) repeater(1) bridge(2) wlanAccessPoint(3) router(4) telephone(5)
	 * docsisCableDevice(6) stationOnly(7).
	 */
	private static function lldpCaps($value): string {
		if (!is_string($value) || $value === '') {
			return '';
		}

		$names = ['other', 'repeater', 'bridge', 'wlan-ap', 'router', 'telephone', 'docsis', 'station'];
		$byte = ord($value[0]);
		$caps = [];

		foreach ($names as $bit => $name) {
			if ($byte & (0x80 >> $bit)) {
				$caps[] = $name;
			}
		}

		return implode(',', $caps);
	}

	private function cdp(): array {
		try {
			$address = $this->session->walkIndex(self::CDP_CACHE.'.4', 2000);
			$device = $this->session->walkIndex(self::CDP_CACHE.'.6', 2000);
			$port = $this->session->walkIndex(self::CDP_CACHE.'.7', 2000);
			$platform = $this->session->walkIndex(self::CDP_CACHE.'.8', 2000);
		}
		catch (SnmpTimeoutException $e) {
			return [];
		}

		$neighbors = [];

		foreach ($device as $index => $device_id) {
			[$if_index] = explode('.', $index);
			$ip = $address[$index] ?? '';
			$ip = (is_string($ip) && strlen($ip) == 4) ? implode('.', array_map('ord', str_split($ip))) : '';

			$neighbors[] = [
				'protocol' => 'cdp',
				'local_port' => $this->ifName($if_index),
				'local_ifindex' => (int) $if_index,
				'remote_chassis' => '',
				'remote_port' => Util::text($port[$index] ?? '', 128),
				'remote_port_desc' => '',
				'remote_sysname' => Util::text($device_id, 255),
				'remote_ip' => Util::isIpv4($ip) ? $ip : '',
				'remote_sysdesc' => Util::text($platform[$index] ?? '', 255),
				'remote_caps' => ''
			];
		}

		if ($neighbors) {
			$this->log[] = sprintf('SNMP CDP: %d neighbors.', count($neighbors));
		}

		return $neighbors;
	}

	/**
	 * @return array  [['port' => .., 'ifindex' => .., 'mac' => .., 'vlan' => ..], ...]
	 */
	private function fdb(): array {
		$entries = [];

		try {
			$base_port_if = $this->session->walkIndex(self::DOT1D_BASE_PORT_IFINDEX, 4000);

			// Q-BRIDGE-MIB (index: fdbId.m1.m2.m3.m4.m5.m6).
			$ports = $this->session->walkIndex(self::DOT1Q_TP_FDB_PORT, 50000);
			$status = $ports ? $this->session->walkIndex(self::DOT1Q_TP_FDB_STATUS, 50000) : [];

			foreach ($ports as $index => $bridge_port) {
				$parts = explode('.', $index);

				if (count($parts) != 7) {
					continue;
				}

				$this->addFdbEntry($entries, array_slice($parts, 1), (int) $bridge_port, (int) ($status[$index] ?? 3),
					$parts[0], $base_port_if
				);
			}

			// BRIDGE-MIB (index: m1..m6), per VLAN community indexing on Cisco.
			if (!$entries) {
				$sessions = [$this->session];

				if (in_array($this->vendor, ['cisco', 'rockwell'], true) && $this->session->getCommunity() !== null) {
					foreach ($this->session->walkIndex(self::CISCO_VTP_VLAN_STATE, 4096) as $index => $state) {
						$vlan = (int) substr($index, strrpos($index, '.') + 1);

						if ($state == 1 && ($vlan < 1002 || $vlan > 1005)) {
							$sessions[$vlan] = $this->session->withCommunity($this->session->getCommunity().'@'.$vlan);
						}
					}
				}

				foreach ($sessions as $vlan => $session) {
					try {
						$vlan_base_port_if = ($session === $this->session)
							? $base_port_if
							: $session->walkIndex(self::DOT1D_BASE_PORT_IFINDEX, 4000);
						$ports = $session->walkIndex(self::DOT1D_TP_FDB_PORT, 50000);
						$status = $ports ? $session->walkIndex(self::DOT1D_TP_FDB_STATUS, 50000) : [];
					}
					catch (SnmpTimeoutException $e) {
						continue;
					}

					foreach ($ports as $index => $bridge_port) {
						$parts = explode('.', $index);

						if (count($parts) == 6) {
							$this->addFdbEntry($entries, $parts, (int) $bridge_port, (int) ($status[$index] ?? 3),
								$vlan === 0 ? '' : (string) $vlan, $vlan_base_port_if
							);
						}
					}
				}
			}
		}
		catch (SnmpTimeoutException $e) {
			$this->log[] = 'SNMP BRIDGE-MIB: '.$e->getMessage();
		}

		$this->log[] = sprintf('SNMP BRIDGE-MIB: %d MAC table entries.', count($entries));

		return array_values($entries);
	}

	private function addFdbEntry(array &$entries, array $octets, int $bridge_port, int $status, string $vlan,
			array $base_port_if): void {
		if ($bridge_port == 0 || in_array($status, self::FDB_STATUS_SELF, true)) {
			return;
		}

		$mac = implode(':', array_map(static fn($o) => sprintf('%02x', (int) $o), $octets));
		$if_index = (int) ($base_port_if[(string) $bridge_port] ?? $bridge_port);
		$port = $this->ifName($if_index);

		$entries[$port.'|'.$mac] = ['port' => $port, 'ifindex' => $if_index, 'mac' => $mac, 'vlan' => $vlan];
	}

	/**
	 * @return array  [['ip' => .., 'mac' => ..], ...]
	 */
	private function arp(): array {
		$entries = [];

		try {
			foreach ($this->session->walkIndex(self::IP_NET_TO_MEDIA_PHYS, 20000) as $index => $value) {
				$parts = explode('.', $index);
				$ip = implode('.', array_slice($parts, -4));
				$mac = Util::macFromSnmp($value);

				if ($mac !== null && Util::isIpv4($ip)) {
					$entries[$ip] = ['ip' => $ip, 'mac' => $mac];
				}
			}

			if (!$entries) {
				// ipNetToPhysicalTable index: ifIndex.addrType(1).len(4).a.b.c.d
				foreach ($this->session->walkIndex(self::IP_NET_TO_PHYSICAL_PHYS, 20000) as $index => $value) {
					$parts = explode('.', $index);

					if (count($parts) == 7 && $parts[1] == 1 && $parts[2] == 4) {
						$ip = implode('.', array_slice($parts, 3));
						$mac = Util::macFromSnmp($value);

						if ($mac !== null && Util::isIpv4($ip)) {
							$entries[$ip] = ['ip' => $ip, 'mac' => $mac];
						}
					}
				}
			}
		}
		catch (SnmpTimeoutException $e) {
		}

		if ($entries) {
			$this->log[] = sprintf('SNMP ARP: %d entries.', count($entries));
		}

		return array_values($entries);
	}
}
