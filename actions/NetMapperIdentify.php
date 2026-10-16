<?php declare(strict_types = 0);


namespace Modules\NetMapper\Actions;

use Modules\NetMapper\Includes\BaseJsonController,
	Modules\NetMapper\Includes\HostLookup,
	Modules\NetMapper\Includes\Identifier,
	Modules\NetMapper\Includes\Util;

/**
 * Detailed, read-only identification of one device (SNMP, HTTP/HTTPS, SSH/Telnet banners, EtherNet/IP).
 */
class NetMapperIdentify extends BaseJsonController {

	protected function getValidationRules(): array {
		return [
			'ip' =>					'required|string|not_empty',
			'ports' =>				'array',
			'community_index' =>	'int32',
			'probe_snmp' =>			'in 0,1'
		] + self::credentialRules();
	}

	protected function doAction(): void {
		$this->extendTimeLimit(120);
		$ip = $this->getInput('ip');

		if (!Util::isIpv4($ip)) {
			$this->respondError(_('Invalid IP address.'));

			return;
		}

		$ports = array_values(array_filter(array_map('intval', $this->getInput('ports', [])),
			static fn($port) => $port > 0 && $port < 65536
		));

		$community_index = $this->hasInput('community_index') ? (int) $this->getInput('community_index') : null;

		try {
			$identifier = new Identifier();
			$result = $identifier->identify($ip, $ports, $this->getSnmpCredentials(), $community_index,
				$this->getInput('probe_snmp', 1) == 1
			);

			$result['host'] = HostLookup::byIp([$ip])[$ip] ?? null;
			$result['log'] = $identifier->getLog();

			$this->respond($result);
		}
		catch (\Throwable $e) {
			$this->respondError($e->getMessage());
		}
	}
}
