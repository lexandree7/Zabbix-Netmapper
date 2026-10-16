<?php declare(strict_types = 0);


namespace Modules\NetMapper\Actions;

use CProfile,
	Modules\NetMapper\Includes\BaseJsonController,
	Modules\NetMapper\Includes\Util;

/**
 * Optional persistence of SNMP communities in the profile of the current user. Nothing else is persisted.
 */
class NetMapperSettingsUpdate extends BaseJsonController {

	protected function getValidationRules(): array {
		return [
			'communities' =>	'string',
			'remember' =>		'required|in 0,1'
		];
	}

	protected function doAction(): void {
		if ($this->getInput('remember') == 1) {
			$value = implode(',', Util::parseCommunities($this->getInput('communities', '')));

			if (strlen($value) > 255) {
				$this->respondError(_('SNMP communities are too long to be remembered (maximum 255 characters).'));

				return;
			}

			CProfile::update(NetMapperView::PROFILE_COMMUNITIES, $value, PROFILE_TYPE_STR);
		}
		else {
			CProfile::delete(NetMapperView::PROFILE_COMMUNITIES);
		}

		$this->respond(['saved' => true]);
	}
}
