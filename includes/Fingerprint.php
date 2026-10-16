<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Vendor / device type classification from SNMP, banners, HTTP data, EtherNet/IP identity and open ports.
 */
final class Fingerprint {

	/**
	 * SNMP private enterprise numbers (IANA) of relevant IT/OT vendors.
	 */
	private const ENTERPRISES = [
		9 => 'cisco', 14988 => 'mikrotik', 248 => 'hirschmann', 4329 => 'siemens', 15004 => 'ruggedcom',
		8691 => 'moxa', 4346 => 'phoenix', 16177 => 'westermo', 95 => 'rockwell', 2011 => 'huawei',
		25506 => 'hpe_comware', 11 => 'hp', 47196 => 'aruba', 2636 => 'juniper', 1916 => 'extreme',
		674 => 'dell', 41112 => 'ubiquiti', 12356 => 'fortinet', 25461 => 'paloalto', 2620 => 'checkpoint',
		8072 => 'netsnmp', 311 => 'microsoft', 207 => 'alliedtelesis', 6486 => 'alcatel', 6527 => 'nokia',
		4526 => 'netgear', 171 => 'dlink', 11863 => 'tplink', 890 => 'zyxel', 3833 => 'schneider',
		10297 => 'advantech', 13576 => 'wago', 1991 => 'brocade', 30065 => 'arista', 244 => 'lantronix',
		332 => 'digi'
	];

	/**
	 * Text patterns (sysDescr, banners, HTTP title/server, certificates, CLI "show version").
	 * Order matters: the first match wins, so more specific rules come first.
	 */
	private const TEXT_RULES = [
		['/stratix/i', 'rockwell', 'switch'],
		['/allen[- ]bradley|rockwell|controllogix|compactlogix|guardlogix|micro8\d0|1756-|1769-|panelview/i', 'rockwell', null],
		['/ruggedcom|\bROS v?\d|RSG\d{4}|RS\d{3,4}[A-Z]?\b|RX1\d{3}|RST\d{4}/i', 'ruggedcom', 'switch'],
		['/scalance\s*[xmswr]|scalance/i', 'siemens', 'switch'],
		['/simatic|siemens|s7-\d{3,4}|cp\s?\d{3}-\d|et\s?200|logo!/i', 'siemens', null],
		['/hirschmann|hios|classic switch|octopus|greyhound|mach\s?\d{3,4}|\bRS\d{2}-|\bRSP\d|\bRSPE|bobcat|spider|eagle\d|dragon/i', 'hirschmann', 'switch'],
		['/mikrotik|routeros|rosssh/i', 'mikrotik', null],
		['/moxa|\bEDS-\d|\bIKS-\d|\bICS-|\bPT-\d{4}|nport|\bAWK-/i', 'moxa', null],
		['/phoenix contact|fl switch|fl mguard|mguard|\bFL \w+/i', 'phoenix', null],
		['/westermo|weos|lynx|redfox|viper-\d|wolverine/i', 'westermo', null],
		['/n-tron|red lion|\bNT24k|\bSLX-/i', 'redlion', 'switch'],
		['/belden|garrettcom|magnum\s?\d/i', 'belden', 'switch'],
		['/schneider|modicon|telemecanique|\bM580\b|\bM340\b|\bBMX|ConneXium/i', 'schneider', null],
		['/weidm[uü]ller|\bIE-SW/i', 'weidmuller', 'switch'],
		['/\bwago\b|750-\d{3}|PFC200/i', 'wago', null],
		['/\bB&R\b|bernecker|X20CP/i', 'br', 'plc'],
		['/\bABB\b|\bAC500\b|\bRTU5\d\d/i', 'abb', null],
		['/omron/i', 'omron', null],
		['/beckhoff|twincat/i', 'beckhoff', null],
		['/advantech|\bEKI-/i', 'advantech', null],
		['/cisco nx-os|nexus/i', 'cisco', 'switch'],
		['/cisco ios|catalyst|cisco|ios-xe|c\d{4}[a-z]*-/i', 'cisco', null],
		['/huawei|\bVRP\b/i', 'huawei', null],
		['/comware|\bH3C\b/i', 'hpe_comware', 'switch'],
		['/procurve|aruba|arubaos/i', 'aruba', 'switch'],
		['/junos|juniper/i', 'juniper', null],
		['/fortigate|fortinet|fortios/i', 'fortinet', 'firewall'],
		['/palo alto|pan-os/i', 'paloalto', 'firewall'],
		['/ubiquiti|unifi|edgeswitch|edgeos/i', 'ubiquiti', null],
		['/allied telesis|alliedware/i', 'alliedtelesis', 'switch'],
		['/extreme networks|exos|extremexos/i', 'extreme', 'switch'],
		['/arista/i', 'arista', 'switch'],
		['/zyxel/i', 'zyxel', null],
		['/tp-link|tplink|jetstream/i', 'tplink', null],
		['/d-link|dlink/i', 'dlink', null],
		['/netgear/i', 'netgear', null],
		['/windows|microsoft/i', 'microsoft', 'server'],
		['/linux|ubuntu|debian|red hat|centos|openssh/i', 'linux', 'server'],
		['/vmware|esxi/i', 'vmware', 'server']
	];

	/**
	 * Device type text patterns.
	 */
	private const TYPE_RULES = [
		['/firewall|fortigate|pan-os|asa\s?\d|mguard|security appliance/i', 'firewall'],
		['/panelview|\bhmi\b|wincc|simatic\s+(?:comfort|basic|mobile)\s+panel|\bktp\d|\btp\d{3,4}|magelis|harmony\s?gto/i', 'hmi'],
		['/controllogix|compactlogix|guardlogix|micro8\d0|s7-\d{3,4}|\bcpu\s?\d{3,4}|\bplc\b|modicon|\bm580\b|\bm340\b|pfc200|x20cp|ac500|logo!/i', 'plc'],
		['/\bswitch|catalyst|stratix|scalance\s*x|nexus|\bEDS-|\bIKS-|ruggedswitch|\bRSG\d|\bRS\d{3,4}|fl switch|\bcrs\d{3}|\bcss\d{3}|octopus|greyhound|\bmach\s?\d|bobcat|spider|lynx|procurve|edgeswitch|jetstream|\bIE-\d{4}|\bIE\d{4}/i', 'switch'],
		['/router|\bisr\d|\basr\d|\bccr\d|\brb\d{3,4}|hex|routeros|scalance\s*m|\bRX1\d{3}|\bvpn\b/i', 'router'],
		['/access point|aironet|\bAP\d{3}|unifi ap|\bAWK-|wireless|scalance\s*w/i', 'ap'],
		['/printer|jetdirect|laserjet|xerox|ricoh|brother|kyocera|lexmark/i', 'printer'],
		['/camera|axis|hikvision|dahua|ip cam|network video/i', 'camera'],
		['/nport|serial device server|gateway|\bmgate|anybus|protocol converter/i', 'gateway'],
		['/ups|apc smart|powerchute|network management card/i', 'ups'],
		['/windows|linux|ubuntu|debian|esxi|vmware|server/i', 'server']
	];

	/**
	 * EtherNet/IP (CIP) device type codes.
	 */
	public const ENIP_DEVICE_TYPES = [
		0x00 => 'Generic Device (deprecated)', 0x02 => 'AC Drive', 0x07 => 'General Purpose Discrete I/O',
		0x0C => 'Communications Adapter', 0x0E => 'Programmable Logic Controller', 0x13 => 'DC Drive',
		0x18 => 'Human-Machine Interface', 0x1B => 'Safety Discrete I/O', 0x22 => 'Managed Ethernet Switch',
		0x2B => 'Generic Device (keyable)', 0x96 => 'Process Control Value'
	];

	private const ENIP_TYPE_MAP = [0x0E => 'plc', 0x18 => 'hmi', 0x22 => 'switch', 0x0C => 'gateway', 0x02 => 'drive',
		0x13 => 'drive', 0x07 => 'io', 0x1B => 'io'
	];

	private const ENIP_VENDORS = [1 => 'rockwell'];

	public const VENDOR_NAMES = [
		'cisco' => 'Cisco', 'mikrotik' => 'MikroTik', 'hirschmann' => 'Hirschmann (Belden)', 'siemens' => 'Siemens',
		'ruggedcom' => 'Siemens RUGGEDCOM', 'moxa' => 'Moxa', 'phoenix' => 'Phoenix Contact', 'westermo' => 'Westermo',
		'rockwell' => 'Rockwell Automation', 'huawei' => 'Huawei', 'hpe_comware' => 'HPE Comware', 'hp' => 'HP',
		'aruba' => 'HPE Aruba', 'juniper' => 'Juniper', 'extreme' => 'Extreme Networks', 'dell' => 'Dell',
		'ubiquiti' => 'Ubiquiti', 'fortinet' => 'Fortinet', 'paloalto' => 'Palo Alto', 'checkpoint' => 'Check Point',
		'netsnmp' => 'Net-SNMP', 'microsoft' => 'Microsoft', 'alliedtelesis' => 'Allied Telesis',
		'alcatel' => 'Alcatel-Lucent', 'nokia' => 'Nokia', 'netgear' => 'Netgear', 'dlink' => 'D-Link',
		'tplink' => 'TP-Link', 'zyxel' => 'Zyxel', 'schneider' => 'Schneider Electric', 'advantech' => 'Advantech',
		'wago' => 'WAGO', 'brocade' => 'Brocade', 'arista' => 'Arista', 'lantronix' => 'Lantronix', 'digi' => 'Digi',
		'redlion' => 'Red Lion / N-Tron', 'belden' => 'Belden', 'weidmuller' => 'Weidmüller', 'br' => 'B&R',
		'abb' => 'ABB', 'omron' => 'Omron', 'beckhoff' => 'Beckhoff', 'linux' => 'Linux', 'vmware' => 'VMware'
	];

	/**
	 * Vendors for which a CLI profile exists (see VendorProfiles).
	 */
	public static function vendorName(?string $vendor): string {
		return $vendor !== null ? (self::VENDOR_NAMES[$vendor] ?? $vendor) : '';
	}

	/**
	 * @param array $info  keys: sysdescr, sysobjectid, sysservices, bridge_ports, lldp, texts (string[]), ports (int[]),
	 *                     enip (array|null), mac (string|null)
	 *
	 * @return array  ['vendor' => ?string, 'vendor_name' => string, 'type' => string, 'network_device' => bool]
	 */
	public static function classify(array $info): array {
		$vendor = null;
		$type = null;
		$texts = array_filter(array_merge([$info['sysdescr'] ?? ''], $info['texts'] ?? []));
		$haystack = implode("\n", $texts);

		// 1. EtherNet/IP identity is very reliable on OT devices.
		if (!empty($info['enip'])) {
			$vendor = self::ENIP_VENDORS[$info['enip']['vendor_id']] ?? null;
			$type = self::ENIP_TYPE_MAP[$info['enip']['device_type']] ?? null;
			$haystack .= "\n".$info['enip']['product_name'];
		}

		// 2. Text rules.
		foreach (self::TEXT_RULES as [$pattern, $rule_vendor, $rule_type]) {
			if ($haystack !== '' && preg_match($pattern, $haystack)) {
				$vendor = $vendor ?? $rule_vendor;
				$type = $type ?? $rule_type;
				break;
			}
		}

		// 3. SNMP enterprise number.
		$objectid = $info['sysobjectid'] ?? '';

		if ($objectid !== '' && preg_match('/^1\.3\.6\.1\.4\.1\.(\d+)/', $objectid, $m)) {
			$enterprise_vendor = self::ENTERPRISES[(int) $m[1]] ?? null;

			if ($enterprise_vendor !== null && ($vendor === null || in_array($vendor, ['linux', 'netsnmp'], true))) {
				$vendor = $enterprise_vendor;
			}
		}

		// 4. Device type text rules.
		if ($type === null && $haystack !== '') {
			foreach (self::TYPE_RULES as [$pattern, $rule_type]) {
				if (preg_match($pattern, $haystack)) {
					$type = $rule_type;
					break;
				}
			}
		}

		// 5. SNMP capabilities: BRIDGE-MIB ports / sysServices (bit 2 = L2, bit 3 = L3).
		$services = (int) ($info['sysservices'] ?? 0);
		$bridge_ports = (int) ($info['bridge_ports'] ?? 0);

		if ($type === null || $type === 'server') {
			if ($bridge_ports > 2 && !in_array($vendor, ['microsoft', 'linux', 'netsnmp', 'vmware'], true)) {
				$type = 'switch';
			}
			elseif ($type === null && ($services & 4) && !($services & 64)) {
				$type = 'router';
			}
			elseif ($type === null && ($services & 2)) {
				$type = 'switch';
			}
		}

		// 6. Open ports.
		$ports = $info['ports'] ?? [];

		if ($type === null && $ports) {
			if (array_intersect($ports, [102, 502, 44818, 20000])) {
				$type = 'plc';
			}
			elseif (in_array(9100, $ports)) {
				$type = 'printer';
			}
			elseif (in_array(554, $ports)) {
				$type = 'camera';
			}
			elseif (array_intersect($ports, [3389, 445, 135])) {
				$type = 'server';
				$vendor = $vendor ?? 'microsoft';
			}
		}

		// 7. MAC OUI.
		if ($vendor === null && !empty($info['mac'])) {
			$vendor = Oui::vendorKey($info['mac']);
		}

		$type = $type ?? 'unknown';

		return [
			'vendor' => $vendor,
			'vendor_name' => self::vendorName($vendor),
			'type' => $type,
			'network_device' => in_array($type, ['switch', 'router', 'firewall', 'ap'], true)
		];
	}
}
