<?php declare(strict_types = 0);


namespace Modules\NetMapper\Actions;

use Modules\NetMapper\Includes\BaseJsonController,
	Modules\NetMapper\Includes\ArraySnmpSession,
	Modules\NetMapper\Includes\HostLookup,
	Modules\NetMapper\Includes\NeighborCollector,
	Modules\NetMapper\Includes\ProxyWalk,
	Modules\NetMapper\Includes\SnmpProbe,
	Modules\NetMapper\Includes\SnmpSession,
	Modules\NetMapper\Includes\SnmpTimeoutException,
	Modules\NetMapper\Includes\Topology,
	Modules\NetMapper\Includes\Util;

/**
 * "Find neighbors": LLDP/CDP neighbors, MAC table and ARP of a switch via SNMP (read-only).
 */
class NetMapperNeighbors extends BaseJsonController {

	protected function getValidationRules(): array {
		return [
			'ip' =>					'required|string|not_empty',
			'vendor' =>				'string',
			'community_index' =>	'int32',
			'with_fdb' =>			'in 0,1',
			'proxyid' =>			'id',
			'hostid' =>				'id',
			'step' =>				'in start,poll,stop'
		] + self::credentialRules();
	}

	protected function doAction(): void {
		$this->extendTimeLimit(300);
		$ip = $this->getInput('ip');

		if (!Util::isIpv4($ip)) {
			$this->respondError(_('Invalid IP address.'));

			return;
		}

		$vendor = $this->getInput('vendor', '');

		if ($this->hasInput('proxyid') || $this->hasInput('hostid')) {
			$this->doProxy($ip, $vendor);

			return;
		}

		try {
			$credentials = $this->getSnmpCredentials();
			$session = null;
			$community_index = null;

			if ($this->hasInput('community_index') || $credentials['version'] == 3) {
				$community_index = (int) $this->getInput('community_index', 0);
				$session = SnmpSession::create($ip, $credentials, $community_index);
			}
			else {
				// Unknown community (e.g. device found through LLDP): try the configured ones in order.
				foreach (array_keys($credentials['communities']) as $index) {
					$candidate = SnmpSession::create($ip, $credentials, $index);

					try {
						if ($candidate->get([SnmpProbe::SYSTEM_OIDS['objectid']])[SnmpProbe::SYSTEM_OIDS['objectid']] !== null) {
							$session = $candidate;
							$community_index = $index;
							break;
						}
					}
					catch (SnmpTimeoutException $e) {
					}
				}

				if ($session === null) {
					$this->respondError(sprintf(_('No SNMP response from %1$s.'), $ip));

					return;
				}
			}

			$collector = new NeighborCollector($session, $vendor !== '' ? $vendor : null);
			$data = $collector->collect($this->getInput('with_fdb', 1) == 1);

			$response = self::buildResponse($ip, $data, $collector->getLog());
			$response['community_index'] = ($credentials['version'] == 3) ? null : $community_index;

			$this->respond($response);
		}
		catch (\Throwable $e) {
			$this->respondError($e->getMessage());
		}
	}

	/**
	 * Neighbor collection through a proxy: step=start creates a temporary host with walk[] items monitored by the
	 * proxy, step=poll reads the collected values (and builds the result once complete), step=stop removes the host.
	 */
	private function doProxy(string $ip, string $vendor): void {
		$step = $this->getInput('step', 'start');

		try {
			if ($step === 'start') {
				$credentials = $this->getSnmpCredentials();

				if ($credentials['version'] == 3) {
					throw new \InvalidArgumentException(_('SNMPv3 is not supported through a proxy (the secrets would '
						.'be stored in a temporary host). Use SNMP v1/v2c or the frontend server as Source.'
					));
				}

				if (!$this->hasInput('proxyid')) {
					throw new \InvalidArgumentException(_('Select a proxy.'));
				}

				$index = (int) $this->getInput('community_index', 0);
				$community = $credentials['communities'][$index] ?? ($credentials['communities'][0] ?? 'public');
				$hostid = ProxyWalk::start($this->getInput('proxyid'), $ip, (int) $credentials['version'], $community);

				$this->respond(['step' => 'start', 'hostid' => $hostid, 'community_index' => $index]);

				return;
			}

			if (!$this->hasInput('hostid')) {
				throw new \InvalidArgumentException(_('Temporary host ID is missing.'));
			}

			$hostid = $this->getInput('hostid');

			if ($step === 'stop') {
				ProxyWalk::stop($hostid);
				$this->respond(['step' => 'stop', 'stopped' => true]);

				return;
			}

			$state = ProxyWalk::poll($hostid);

			if (!$state['done']) {
				$this->respond(['step' => 'poll', 'done' => false, 'collected' => $state['collected'],
					'failed' => $state['failed'], 'total' => $state['total'], 'errors' => $state['errors']
				]);

				return;
			}

			ProxyWalk::stop($hostid);

			if (!$state['values']) {
				throw new \RuntimeException(_('The proxy returned no SNMP data (check community, SNMP access from the '
					.'proxy and the temporary items state). ').implode(' ', $state['errors'])
				);
			}

			$collector = new NeighborCollector(new ArraySnmpSession($ip, $state['values']), $vendor !== '' ? $vendor : null);
			$data = $collector->collect(true);

			$response = self::buildResponse($ip, $data, $collector->getLog());
			$response += ['step' => 'poll', 'done' => true, 'errors' => $state['errors']];

			$this->respond($response);
		}
		catch (\Throwable $e) {
			$this->respondError($e->getMessage());
		}
	}

	/**
	 * Shared with NetMapperCliParse.
	 */
	public static function buildResponse(string $ip, array $data, array $log): array {
		$analysis = Topology::analyze($data['neighbors'], $data['fdb'], $data['arp'], $data['own_macs']);

		$ips = array_merge(array_column($data['neighbors'], 'remote_ip'), array_column($analysis['access'], 'ip'));

		return [
			'ip' => $ip,
			'neighbors' => $data['neighbors'],
			'ports' => $analysis['ports'],
			'access' => $analysis['access'],
			'arp' => $data['arp'],
			'own_macs' => array_slice($data['own_macs'], 0, 512),
			'local' => $data['local'] ?? null,
			'hosts' => HostLookup::byIp(array_filter($ips)),
			'log' => $log
		];
	}
}
