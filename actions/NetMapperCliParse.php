<?php declare(strict_types = 0);


namespace Modules\NetMapper\Actions;

use Modules\NetMapper\Includes\BaseJsonController,
	Modules\NetMapper\Includes\CliParsers,
	Modules\NetMapper\Includes\Fingerprint,
	Modules\NetMapper\Includes\Util,
	Modules\NetMapper\Includes\VendorProfiles;

/**
 * Parses CLI output pasted by the user (the module itself never connects to device CLIs).
 * The pasted text is processed in memory only and is not stored.
 */
class NetMapperCliParse extends BaseJsonController {

	protected function getValidationRules(): array {
		return [
			'ip' =>				'required|string|not_empty',
			'vendor' =>			'string',
			'text_version' =>	'string',
			'text_lldp' =>		'string',
			'text_cdp' =>		'string',
			'text_mac' =>		'string',
			'text_arp' =>		'string',
			'own_macs' =>		'array'
		];
	}

	protected function doAction(): void {
		$ip = $this->getInput('ip');

		if (!Util::isIpv4($ip)) {
			$this->respondError(_('Invalid IP address.'));

			return;
		}

		$vendor = VendorProfiles::resolve($this->getInput('vendor', '') ?: null);
		$log = [];
		$classification = null;
		$hostname = '';
		$version_macs = [];

		$version = $this->getInput('text_version', '');

		if (trim($version) !== '') {
			$parsed = CliParsers::parseVersion($version);
			$hostname = $parsed['hostname'];
			$version_macs = $parsed['macs'];
			$classification = Fingerprint::classify(['texts' => [$parsed['text']]]);

			if ($classification['vendor'] !== null && $vendor === 'generic') {
				$vendor = VendorProfiles::resolve($classification['vendor']);
			}
		}

		$neighbors = array_merge(
			CliParsers::parseNeighbors($this->getInput('text_lldp', ''), $vendor, 'lldp'),
			CliParsers::parseNeighbors($this->getInput('text_cdp', ''), $vendor, 'cdp')
		);
		$fdb = CliParsers::parseMacTable($this->getInput('text_mac', ''), $vendor);
		$arp = CliParsers::parseArp($this->getInput('text_arp', ''));

		$log[] = sprintf('CLI (%s): %d neighbors, %d MAC table entries, %d ARP entries.', $vendor, count($neighbors),
			count($fdb), count($arp)
		);

		$own_macs = array_values(array_unique(array_merge($version_macs,
			array_filter(array_map([Util::class, 'normalizeMac'], $this->getInput('own_macs', [])))
		)));

		$response = NetMapperNeighbors::buildResponse($ip, [
			'neighbors' => $neighbors,
			'fdb' => $fdb,
			'arp' => $arp,
			'own_macs' => $own_macs,
			'local' => [
				'chassis_id' => $version_macs[0] ?? '',
				'sysname' => $hostname,
				'lldp_sysname' => '',
				'bridge_mac' => null,
				'port_ids' => []
			]
		], $log);

		$response['classification'] = $classification;
		$response['hostname'] = $hostname;

		$this->respond($response);
	}
}
