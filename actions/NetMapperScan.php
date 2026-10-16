<?php declare(strict_types = 0);


namespace Modules\NetMapper\Actions;

use Modules\NetMapper\Includes\BaseJsonController,
	Modules\NetMapper\Includes\Config,
	Modules\NetMapper\Includes\Fingerprint,
	Modules\NetMapper\Includes\HostLookup,
	Modules\NetMapper\Includes\IpRange,
	Modules\NetMapper\Includes\ProxyDiscovery,
	Modules\NetMapper\Includes\ProxyScript,
	Modules\NetMapper\Includes\ProxyScriptSetupException,
	Modules\NetMapper\Includes\Scanner,
	Modules\NetMapper\Includes\SnmpProbe,
	Modules\NetMapper\Includes\SnmpSession,
	Modules\NetMapper\Includes\SnmpTimeoutException,
	Modules\NetMapper\Includes\SnmpTransportException,
	Modules\NetMapper\Includes\Util;

/**
 * Liveness scan.
 *  - source=server: the browser sends the target list in chunks (ips[]); probes run from the frontend server.
 *  - source=proxy:  step=start creates a temporary discovery rule on the proxy, step=poll returns results,
 *                   step=stop deletes the rule.
 */
class NetMapperScan extends BaseJsonController {

	protected function getValidationRules(): array {
		return [
			'source' =>			'required|in server,proxy,proxy_script',
			'step' =>			'in start,poll,stop,setup',
			'ips' =>			'array',
			'targets' =>		'string',
			'proxyid' =>		'id',
			'druleid' =>		'id',
			'probe_icmp' =>		'in 0,1',
			'probe_tcp' =>		'in 0,1',
			'probe_snmp' =>		'in 0,1',
			'port_profile' =>	'in minimal,standard'
		] + self::credentialRules();
	}

	protected function doAction(): void {
		$this->extendTimeLimit(300);

		try {
			if ($this->getInput('source') === 'proxy') {
				$this->doProxy();
			}
			elseif ($this->getInput('source') === 'proxy_script') {
				$this->doProxyScript();
			}
			else {
				$this->doServer();
			}
		}
		catch (ProxyScriptSetupException $e) {
			$this->respond([
				'error' => $e->getMessage(),
				'setup_required' => true,
				'can_create' => $this->getUserType() == USER_TYPE_SUPER_ADMIN,
				'script' => [
					'name' => ProxyScript::SCRIPT_NAME,
					'command' => ProxyScript::command(),
					'validator' => ProxyScript::validator()
				]
			]);
		}
		catch (\Throwable $e) {
			$this->respondError($e->getMessage());
		}
	}

	private function doServer(): void {
		$ips = array_values(array_unique(array_filter($this->getInput('ips', []), [Util::class, 'isIpv4'])));

		if (!$ips) {
			throw new \InvalidArgumentException(_('No valid IP addresses.'));
		}

		if (count($ips) > Config::get('scan_chunk_size') * 4) {
			throw new \InvalidArgumentException(_('Too many addresses in one request.'));
		}

		$snmp = $this->getSnmpCredentials();
		$alive = [];
		$warnings = [];

		$mark = static function (string $ip, string $reason) use (&$alive) {
			if (!array_key_exists($ip, $alive)) {
				$alive[$ip] = ['ip' => $ip, 'reasons' => [], 'ports' => [], 'snmp' => null];
			}

			$alive[$ip]['reasons'][$reason] = $reason;
		};

		if ($this->getInput('probe_icmp', 1) == 1) {
			foreach (Scanner::fping($ips) as $ip) {
				$mark($ip, 'icmp');
			}
		}

		if ($this->getInput('probe_tcp', 1) == 1) {
			$ports = Config::getPorts($this->getInput('port_profile', 'standard'));
			$tcp = Scanner::tcpProbe($ips, $ports, Config::get('tcp_timeout_ms'), Config::get('tcp_concurrency'));

			foreach ($tcp as $ip => $state) {
				$mark($ip, 'tcp');
				sort($state['open']);
				$alive[$ip]['ports'] = $state['open'];
			}
		}

		if ($this->getInput('probe_snmp', 1) == 1) {
			if ($snmp['version'] == 3) {
				// No parallel SNMPv3 probe: query only hosts already known to be alive.
				foreach (array_keys($alive) as $ip) {
					try {
						$session = SnmpSession::create($ip, $snmp);
						$values = $session->get(array_values(SnmpProbe::SYSTEM_OIDS));

						if (array_filter($values, static fn($v) => $v !== null)) {
							$system = [];

							foreach (SnmpProbe::SYSTEM_OIDS as $key => $oid) {
								$system[$key] = $values[$oid];
							}

							$alive[$ip]['snmp'] = [
								'version' => 3,
								'community_index' => null,
								'system' => SnmpProbe::formatSystem($system)
							];
							$mark($ip, 'snmp');
						}
					}
					catch (SnmpTimeoutException $e) {
					}
				}
			}
			else {
				$found = SnmpProbe::probe($ips, $snmp['communities'], $snmp['version'], Config::get('snmp_timeout_ms'),
					Config::get('snmp_retries')
				);

				foreach ($found as $ip => $info) {
					$mark($ip, 'snmp');
					$alive[$ip]['snmp'] = $info;
				}

				foreach (SnmpProbe::$send_errors as $errno => $error) {
					$warnings[] = trim(sprintf(_('SNMP requests could not be sent (%1$d times): %2$s.'), $error['count'],
						$error['message']
					).' '.SnmpTransportException::hint($errno));
				}
			}
		}

		// Entries completed by ARP during the probes reveal hosts that filter every probe (same L2 segment only).
		$arp = Util::localArpTable();

		foreach ($ips as $ip) {
			if (array_key_exists($ip, $arp)) {
				$mark($ip, 'arp');
				$alive[$ip]['mac'] = $arp[$ip];
			}
		}

		$this->respond([
			'source' => 'server',
			'scanned' => count($ips),
			'results' => $this->finalize($alive),
			'fping' => Scanner::isFpingAvailable(),
			'warnings' => $warnings
		]);
	}

	private function doProxy(): void {
		$step = $this->getInput('step', 'start');

		if ($step === 'start') {
			if (!$this->hasInput('proxyid')) {
				throw new \InvalidArgumentException(_('Select a proxy.'));
			}

			$ranges = IpRange::parse($this->getInput('targets', ''));

			if (IpRange::count($ranges) > Config::get('max_targets')) {
				throw new \InvalidArgumentException(sprintf(_('Too many addresses (maximum %1$d).'),
					Config::get('max_targets')
				));
			}

			$snmp = $this->getSnmpCredentials();
			$druleid = ProxyDiscovery::start($this->getInput('proxyid'), IpRange::toZabbixRange($ranges),
				$this->getInput('probe_tcp', 1) == 1 ? Config::getPorts($this->getInput('port_profile', 'standard')) : [],
				$this->getInput('probe_icmp', 1) == 1, $snmp, $this->getInput('probe_snmp', 1) == 1
			);

			$this->respond([
				'source' => 'proxy',
				'druleid' => $druleid,
				'snmpv3_skipped' => $snmp['version'] == 3 && $this->getInput('probe_snmp', 1) == 1
			]);

			return;
		}

		if (!$this->hasInput('druleid')) {
			throw new \InvalidArgumentException(_('Discovery rule ID is missing.'));
		}

		if ($step === 'stop') {
			ProxyDiscovery::stop($this->getInput('druleid'));
			$this->respond(['source' => 'proxy', 'stopped' => true]);

			return;
		}

		$data = ProxyDiscovery::results($this->getInput('druleid'));
		$alive = [];
		$communities = $this->getSnmpCredentials()['communities'];

		foreach ($data['results'] as $result) {
			if ($result['snmp'] !== null) {
				$index = array_search($result['snmp']['community'], $communities, true);
				$result['snmp']['community_index'] = ($index === false) ? null : $index;
				unset($result['snmp']['community']);
			}

			$result['reasons'] = array_combine($result['reasons'], $result['reasons']);
			$alive[$result['ip']] = $result;
		}

		$this->respond([
			'source' => 'proxy',
			'results' => $this->finalize($alive),
			'diagnostics' => $data['diagnostics']
		]);
	}

	/**
	 * Liveness scan executed on the proxy by the "NetMapper: ping scan" global script (fping).
	 */
	private function doProxyScript(): void {
		if ($this->getInput('step', 'start') === 'setup') {
			$scriptid = ProxyScript::createScript();
			$this->respond(['source' => 'proxy_script', 'scriptid' => $scriptid]);

			return;
		}

		if (!$this->hasInput('proxyid')) {
			throw new \InvalidArgumentException(_('Select a proxy.'));
		}

		$ips = array_values(array_unique(array_filter($this->getInput('ips', []), [Util::class, 'isIpv4'])));

		if (!$ips) {
			throw new \InvalidArgumentException(_('No valid IP addresses.'));
		}

		if (count($ips) > Config::get('scan_chunk_size') * 4) {
			throw new \InvalidArgumentException(_('Too many addresses in one request.'));
		}

		$script = ProxyScript::findScript();
		$host = ProxyScript::findHost($this->getInput('proxyid'));
		$alive = [];

		foreach (ProxyScript::ping($script['scriptid'], $host['hostid'], $ips) as $ip) {
			$alive[$ip] = ['ip' => $ip, 'reasons' => ['icmp' => 'icmp'], 'ports' => [], 'snmp' => null];
		}

		$this->respond([
			'source' => 'proxy_script',
			'scanned' => count($ips),
			'results' => $this->finalize($alive),
			'executed_via' => ['hostid' => $host['hostid'], 'host' => $host['name'], 'script' => $script['name']]
		]);
	}

	private function finalize(array $alive): array {
		$hosts = HostLookup::byIp(array_keys($alive));
		$results = [];

		foreach ($alive as $ip => $entry) {
			$system = $entry['snmp']['system'] ?? [];

			$entry['reasons'] = array_values($entry['reasons']);
			$entry['host'] = $hosts[$ip] ?? null;
			$entry['classification'] = Fingerprint::classify([
				'sysdescr' => $system['sysdescr'] ?? '',
				'sysobjectid' => $system['sysobjectid'] ?? '',
				'sysservices' => $system['sysservices'] ?? 0,
				'ports' => $entry['ports'],
				'mac' => $entry['mac'] ?? null
			]);

			$results[] = $entry;
		}

		usort($results, static fn($a, $b) => ip2long($a['ip']) <=> ip2long($b['ip']));

		return $results;
	}
}
