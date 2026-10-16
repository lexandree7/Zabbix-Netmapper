<?php declare(strict_types = 0);


namespace Modules\NetMapper\Actions;

use API,
	Modules\NetMapper\Includes\BaseJsonController,
	Modules\NetMapper\Includes\Util;

/**
 * Creates a Zabbix host for a discovered device (Zabbix API permissions of the current user apply).
 * SNMP interfaces reference user macros ({$SNMP_COMMUNITY}, {$SNMPV3_*}) instead of secrets.
 */
class NetMapperHostCreate extends BaseJsonController {

	protected function getValidationRules(): array {
		return [
			'host' =>			'required|string|not_empty',
			'name' =>			'string',
			'ip' =>				'required|string|not_empty',
			'groupids' =>		'required|array_id',
			'templateids' =>	'array_id',
			'iface_agent' =>	'in 0,1',
			'iface_snmp' =>		'in 0,1',
			'snmp_version' =>	'in 1,2,3',
			'snmp_community' =>	'string',
			'description' =>	'string'
		];
	}

	protected function doAction(): void {
		$ip = $this->getInput('ip');

		if (!Util::isIpv4($ip)) {
			$this->respondError(_('Invalid IP address.'));

			return;
		}

		$interfaces = [];

		if ($this->getInput('iface_agent', 0) == 1) {
			$interfaces[] = ['type' => INTERFACE_TYPE_AGENT, 'main' => INTERFACE_PRIMARY, 'useip' => INTERFACE_USE_IP,
				'ip' => $ip, 'dns' => '', 'port' => '10050'
			];
		}

		if ($this->getInput('iface_snmp', 0) == 1) {
			$version = (int) $this->getInput('snmp_version', 2);
			$details = ['version' => $version, 'bulk' => SNMP_BULK_ENABLED];

			if ($version == 3) {
				$details += [
					'securityname' => '{$SNMPV3_USER}',
					'securitylevel' => ITEM_SNMPV3_SECURITYLEVEL_AUTHPRIV,
					'authprotocol' => ITEM_SNMPV3_AUTHPROTOCOL_SHA1,
					'authpassphrase' => '{$SNMPV3_AUTHPASS}',
					'privprotocol' => ITEM_SNMPV3_PRIVPROTOCOL_AES128,
					'privpassphrase' => '{$SNMPV3_PRIVPASS}',
					'contextname' => ''
				];
			}
			else {
				$community = trim($this->getInput('snmp_community', ''));
				$details['community'] = ($community !== '') ? $community : '{$SNMP_COMMUNITY}';
			}

			$interfaces[] = ['type' => INTERFACE_TYPE_SNMP, 'main' => INTERFACE_PRIMARY, 'useip' => INTERFACE_USE_IP,
				'ip' => $ip, 'dns' => '', 'port' => '161', 'details' => $details
			];
		}

		$host = [
			'host' => $this->getInput('host'),
			'groups' => array_map(static fn($id) => ['groupid' => $id], $this->getInput('groupids')),
			'templates' => array_map(static fn($id) => ['templateid' => $id], $this->getInput('templateids', [])),
			'interfaces' => $interfaces,
			'description' => $this->getInput('description', '')
		];

		if ($this->getInput('name', '') !== '') {
			$host['name'] = $this->getInput('name');
		}

		$result = API::Host()->create([$host]);

		if (!$result) {
			$messages = function_exists('get_and_clear_messages')
				? array_column(get_and_clear_messages(), 'message')
				: [];

			$this->respondError($messages ? implode(' ', $messages) : _('Cannot add host.'));

			return;
		}

		$hostid = reset($result['hostids']);

		$this->respond([
			'host' => [
				'hostid' => $hostid,
				'host' => $host['host'],
				'name' => $host['name'] ?? $host['host'],
				'status' => HOST_STATUS_MONITORED
			]
		]);
	}
}
