<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Read-only CLI commands suggested to the user, per vendor.
 *
 * The module never connects to device CLIs: the user runs these commands himself (unprivileged / user EXEC mode,
 * no configuration mode, no write commands) and pastes the output into the module, which only parses text.
 *
 * Sections: version, lldp, cdp, mac, arp. Every section lists alternatives (firmware dependent); the user runs the
 * first one accepted by the device. "paging" lists session-only commands that disable output paging (optional).
 */
final class VendorProfiles {

	private const PROFILES = [
		'cisco' => [
			'name' => 'Cisco IOS / IOS-XE / NX-OS, Rockwell Stratix',
			'mode' => 'User EXEC (prompt ending with ">")',
			'paging' => ['terminal length 0'],
			'version' => ['show version'],
			'lldp' => ['show lldp neighbors detail'],
			'cdp' => ['show cdp neighbors detail'],
			'mac' => ['show mac address-table', 'show mac-address-table'],
			'arp' => ['show ip arp', 'show arp']
		],
		'mikrotik' => [
			'name' => 'MikroTik RouterOS (user in "read" group)',
			'mode' => 'Any user of the "read" group',
			'paging' => [],
			'version' => ['/system resource print', '/system routerboard print'],
			'lldp' => ['/ip neighbor print detail without-paging'],
			'cdp' => [],
			'mac' => ['/interface bridge host print detail without-paging',
				'/interface ethernet switch host print detail without-paging'
			],
			'arp' => ['/ip arp print detail without-paging']
		],
		'hirschmann' => [
			'name' => 'Hirschmann HiOS / Classic (Belden)',
			'mode' => 'User mode (prompt ending with ">")',
			'paging' => ['cli numlines 0'],
			'version' => ['show system info', 'show sysinfo'],
			'lldp' => ['show lldp remote-data'],
			'cdp' => [],
			'mac' => ['show mac-addr-table', 'show mac-filter-table'],
			'arp' => ['show ip arp']
		],
		'siemens' => [
			'name' => 'Siemens SCALANCE X / XM / XR / XC',
			'mode' => 'User EXEC (prompt ending with ">")',
			'paging' => ['terminal length 0'],
			'version' => ['show versions', 'show version'],
			'lldp' => ['show lldp neighbors detail', 'show lldp neighbors'],
			'cdp' => [],
			'mac' => ['show mac-address-table'],
			'arp' => ['show ip arp']
		],
		'ruggedcom' => [
			'name' => 'Siemens RUGGEDCOM ROS / ROX',
			'mode' => 'Guest / operator user',
			'paging' => [],
			'version' => ['show version'],
			'lldp' => ['show lldp neighbors', 'show interfaces lldp neighbors'],
			'cdp' => [],
			'mac' => ['show mac-address-table', 'show switch dynamic-mac-address-table'],
			'arp' => ['show arp']
		],
		'rockwell' => [
			'name' => 'Rockwell Automation (Stratix uses the Cisco profile)',
			'mode' => 'User EXEC (prompt ending with ">")',
			'paging' => ['terminal length 0'],
			'version' => ['show version'],
			'lldp' => ['show lldp neighbors detail'],
			'cdp' => ['show cdp neighbors detail'],
			'mac' => ['show mac address-table'],
			'arp' => ['show ip arp']
		],
		'moxa' => [
			'name' => 'Moxa EDS / IKS / PT / ICS',
			'mode' => 'User mode (prompt ending with ">")',
			'paging' => ['terminal length 0'],
			'version' => ['show version', 'show system'],
			'lldp' => ['show lldp entry', 'show lldp neighbors'],
			'cdp' => [],
			'mac' => ['show mac-address-table', 'show mac address-table'],
			'arp' => ['show arp']
		],
		'phoenix' => [
			'name' => 'Phoenix Contact FL SWITCH',
			'mode' => 'User mode',
			'paging' => [],
			'version' => ['show version', 'show system-info'],
			'lldp' => ['show lldp neighbors', 'show lldp remote-data'],
			'cdp' => [],
			'mac' => ['show mac-address-table', 'show fdb'],
			'arp' => ['show arp']
		],
		'westermo' => [
			'name' => 'Westermo WeOS',
			'mode' => 'Admin EXEC view (show commands only)',
			'paging' => [],
			'version' => ['show system-information', 'show version'],
			'lldp' => ['show lldp neighbor', 'show lldp'],
			'cdp' => [],
			'mac' => ['show mac'],
			'arp' => ['show arp']
		],
		'huawei' => [
			'name' => 'Huawei VRP',
			'mode' => 'User view (prompt "<name>")',
			'paging' => ['screen-length 0 temporary'],
			'version' => ['display version'],
			'lldp' => ['display lldp neighbor'],
			'cdp' => [],
			'mac' => ['display mac-address'],
			'arp' => ['display arp']
		],
		'hpe_comware' => [
			'name' => 'HPE Comware / H3C',
			'mode' => 'User view (prompt "<name>")',
			'paging' => ['screen-length disable'],
			'version' => ['display version'],
			'lldp' => ['display lldp neighbor-information verbose'],
			'cdp' => [],
			'mac' => ['display mac-address'],
			'arp' => ['display arp']
		],
		'aruba' => [
			'name' => 'HPE Aruba / ProCurve (AOS-S, AOS-CX)',
			'mode' => 'Operator mode (prompt ending with ">")',
			'paging' => [],
			'version' => ['show version', 'show system'],
			'lldp' => ['show lldp info remote-device detail', 'show lldp neighbor-info detail'],
			'cdp' => [],
			'mac' => ['show mac-address', 'show mac-address-table'],
			'arp' => ['show arp']
		],
		'juniper' => [
			'name' => 'Juniper Junos',
			'mode' => 'Operational mode (read-only class user)',
			'paging' => [],
			'version' => ['show version | no-more'],
			'lldp' => ['show lldp neighbors | no-more'],
			'cdp' => [],
			'mac' => ['show ethernet-switching table | no-more'],
			'arp' => ['show arp no-resolve | no-more']
		],
		'generic' => [
			'name' => 'Generic / other vendors',
			'mode' => 'Unprivileged mode',
			'paging' => [],
			'version' => ['show version'],
			'lldp' => ['show lldp neighbors detail', 'show lldp neighbors', 'show lldp remote-data'],
			'cdp' => ['show cdp neighbors detail'],
			'mac' => ['show mac address-table', 'show mac-address-table', 'show mac-addr-table'],
			'arp' => ['show arp', 'show ip arp']
		]
	];

	/**
	 * Vendor keys mapped to another profile.
	 */
	private const ALIASES = ['hp' => 'aruba', 'belden' => 'hirschmann', 'redlion' => 'generic'];

	/**
	 * Session-only commands allowed in "paging" besides "show"/"display"/RouterOS "print".
	 */
	private const SESSION_COMMANDS = [
		'terminal length 0', 'cli numlines 0', 'screen-length 0 temporary', 'screen-length disable'
	];

	public static function get(?string $vendor): array {
		$key = self::resolve($vendor);

		return ['vendor' => $key] + self::PROFILES[$key];
	}

	public static function resolve(?string $vendor): string {
		$vendor = self::ALIASES[$vendor] ?? $vendor;

		return ($vendor !== null && array_key_exists($vendor, self::PROFILES)) ? $vendor : 'generic';
	}

	/**
	 * @return array  vendor => display name
	 */
	public static function getList(): array {
		return array_map(static fn(array $profile) => $profile['name'], self::PROFILES);
	}

	/**
	 * All profiles, after a read-only self check of every command.
	 */
	public static function getAll(): array {
		$profiles = [];

		foreach (self::PROFILES as $vendor => $profile) {
			foreach (['version', 'lldp', 'cdp', 'mac', 'arp', 'paging'] as $section) {
				$profile[$section] = array_values(array_filter($profile[$section], [self::class, 'isReadOnly']));
			}

			$profiles[$vendor] = $profile;
		}

		return $profiles;
	}

	/**
	 * Defensive check: a suggested command must be a pure read command.
	 */
	public static function isReadOnly(string $command): bool {
		$command = trim($command);

		if (in_array($command, self::SESSION_COMMANDS, true)) {
			return true;
		}

		if (!preg_match('/^(show|display)\s|^\/[a-z0-9 \-\/]+\sprint(\s|$)/i', $command)) {
			return false;
		}

		// The only pipe allowed is the Junos pager modifier at the end of the command.
		if (preg_match('/[;&<>`$]|\|(?!\s*no-more\s*$)/i', $command)) {
			return false;
		}

		return !preg_match('/\b(conf(ig(ure)?)?|write|copy|erase|delete|reload|reboot|set|add|remove|clear|debug|'
			.'enable|format|rename|save|reset|shutdown|install|upgrade|import|export|tftp|ftp|scp)\b/i',
			preg_replace('/^(show|display)\s+/i', '', $command)
		);
	}
}
