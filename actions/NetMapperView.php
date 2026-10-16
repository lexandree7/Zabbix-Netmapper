<?php declare(strict_types = 0);


namespace Modules\NetMapper\Actions;

use API,
	CController,
	CControllerResponseData,
	CCsrfTokenHelper,
	CProfile,
	Modules\NetMapper\Includes\Config,
	Modules\NetMapper\Includes\ProxyDiscovery,
	Modules\NetMapper\Includes\Scanner,
	Modules\NetMapper\Includes\VendorProfiles;

class NetMapperView extends CController {

	public const PROFILE_COMMUNITIES = 'web.netmapper.snmp.communities';

	private const AJAX_ACTIONS = ['netmapper.scan', 'netmapper.identify', 'netmapper.neighbors', 'netmapper.cli.parse',
		'netmapper.host.create', 'netmapper.map.save', 'netmapper.settings.update'
	];

	protected function init(): void {
		// Read-only page (GET); all state changing requests are separate POST actions with CSRF tokens.
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		return true;
	}

	protected function checkPermissions(): bool {
		return $this->getUserType() >= USER_TYPE_ZABBIX_ADMIN;
	}

	protected function doAction(): void {
		$proxies = [];

		try {
			ProxyDiscovery::cleanup();
			$proxies = ProxyDiscovery::getProxies();
		}
		catch (\Throwable $e) {
		}

		$csrf = [];

		foreach (self::AJAX_ACTIONS as $action) {
			$csrf[$action] = CCsrfTokenHelper::get($action);
		}

		$communities = (string) CProfile::get(self::PROFILE_COMMUNITIES, '');

		$groups = API::HostGroup()->get([
			'output' => ['groupid', 'name'],
			'editable' => true,
			'sortfield' => 'name'
		]);

		$templates = API::Template()->get([
			'output' => ['templateid', 'name'],
			'sortfield' => 'name'
		]);

		$this->setResponse(new CControllerResponseData([
			'title' => _('Network mapper'),
			'proxies' => $proxies,
			'communities' => $communities,
			'remember_communities' => $communities !== '',
			'groups' => $groups ?: [],
			'templates' => $templates ?: [],
			'vendor_profiles' => VendorProfiles::getAll(),
			'csrf' => $csrf,
			'fping' => Scanner::isFpingAvailable(),
			'snmp_ext' => class_exists('SNMP'),
			'max_targets' => Config::get('max_targets'),
			'chunk_size' => Config::get('scan_chunk_size')
		]));
	}
}
