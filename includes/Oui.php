<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Small, best-effort list of IEEE OUIs of common IT/OT vendors. Used only as a hint for devices
 * that are known by MAC address only. Extend as needed (https://standards-oui.ieee.org/).
 */
final class Oui {

	private const TABLE = [
		'00:00:bc' => 'rockwell', '00:1d:9c' => 'rockwell', '5c:88:16' => 'rockwell', 'e4:90:69' => 'rockwell',
		'00:1b:1b' => 'siemens', '00:0e:8c' => 'siemens', '08:00:06' => 'siemens', '28:63:36' => 'siemens',
		'00:0a:dc' => 'ruggedcom',
		'00:80:63' => 'hirschmann',
		'00:a0:45' => 'phoenix',
		'00:90:e8' => 'moxa',
		'00:07:7c' => 'westermo',
		'00:80:f4' => 'schneider',
		'00:30:de' => 'wago',
		'00:60:65' => 'br',
		'00:01:05' => 'beckhoff',
		'00:00:0a' => 'omron',
		'00:20:4a' => 'lantronix',
		'00:40:9d' => 'digi',
		'4c:5e:0c' => 'mikrotik', '6c:3b:6b' => 'mikrotik', 'e4:8d:8c' => 'mikrotik', 'd4:ca:6d' => 'mikrotik',
		'48:8f:5a' => 'mikrotik', 'cc:2d:e0' => 'mikrotik', 'b8:69:f4' => 'mikrotik', '2c:c8:1b' => 'mikrotik',
		'64:d1:54' => 'mikrotik', '74:4d:28' => 'mikrotik', 'dc:2c:6e' => 'mikrotik', '18:fd:74' => 'mikrotik',
		'00:0c:42' => 'mikrotik',
		'00:00:0c' => 'cisco', '00:1b:54' => 'cisco', '00:1e:13' => 'cisco', '00:22:90' => 'cisco',
		'00:50:56' => 'vmware', '00:0c:29' => 'vmware'
	];

	public static function vendorKey(?string $mac): ?string {
		if ($mac === null || strlen($mac) < 8) {
			return null;
		}

		return self::TABLE[strtolower(substr($mac, 0, 8))] ?? null;
	}

	/**
	 * Locally administered or multicast addresses are typically virtual / not useful for identification.
	 */
	public static function isLocallyAdministered(string $mac): bool {
		return (bool) (hexdec(substr($mac, 0, 2)) & 0x02);
	}
}
