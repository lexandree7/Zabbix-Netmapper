<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

use CController,
	CControllerResponseData;

/**
 * Base class of all AJAX actions of the module.
 *
 * - CSRF validation stays enabled (POST + per-action "_csrf_token" is mandatory).
 * - Only Zabbix Admin / Super admin users can probe the network.
 * - SNMPv3 secrets received in requests are never stored, logged or returned.
 */
abstract class BaseJsonController extends CController {

	/**
	 * Validation rules in CNewValidator format.
	 */
	abstract protected function getValidationRules(): array;

	protected function checkInput(): bool {
		$ret = $this->validateInput($this->getValidationRules());

		if (!$ret) {
			$messages = [];

			if (function_exists('get_and_clear_messages')) {
				$messages = array_column(get_and_clear_messages(), 'message');
			}

			$this->respondError($messages ? implode(' ', $messages) : _('Incorrect request parameters.'));
		}

		return $ret;
	}

	protected function checkPermissions(): bool {
		return $this->getUserType() >= USER_TYPE_ZABBIX_ADMIN;
	}

	protected function respond(array $payload): void {
		$json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
			| JSON_PARTIAL_OUTPUT_ON_ERROR
		);

		$this->setResponse(new CControllerResponseData(['main_block' => $json]));
	}

	protected function respondError(string $message): void {
		$this->respond(['error' => $message]);
	}

	/**
	 * Raises execution time limit for long running network operations (when allowed by PHP configuration).
	 */
	protected function extendTimeLimit(int $seconds): void {
		if (function_exists('set_time_limit')) {
			@set_time_limit($seconds);
		}

		@ignore_user_abort(false);
	}

	/**
	 * Common validation rules for SNMP credentials.
	 */
	protected static function credentialRules(): array {
		return [
			'communities' =>	'string',
			'snmp_version' =>	'in 1,2,3',
			'v3_user' =>		'string',
			'v3_level' =>		'in 0,1,2',
			'v3_auth_proto' =>	'in MD5,SHA,SHA224,SHA256,SHA384,SHA512',
			'v3_auth_pass' =>	'string',
			'v3_priv_proto' =>	'in DES,AES,AES192,AES256',
			'v3_priv_pass' =>	'string',
			'v3_context' =>		'string'
		];
	}

	/**
	 * Builds the SNMP credential set from request input.
	 *
	 * @return array  ['version' => 1|2|3, 'communities' => string[], 'v3' => array|null]
	 */
	protected function getSnmpCredentials(): array {
		$version = (int) $this->getInput('snmp_version', 2);
		$v3 = null;

		if ($version == 3) {
			$v3 = [
				'user' => $this->getInput('v3_user', ''),
				'level' => (int) $this->getInput('v3_level', 2),
				'auth_proto' => $this->getInput('v3_auth_proto', 'SHA'),
				'auth_pass' => $this->getInput('v3_auth_pass', ''),
				'priv_proto' => $this->getInput('v3_priv_proto', 'AES'),
				'priv_pass' => $this->getInput('v3_priv_pass', ''),
				'context' => $this->getInput('v3_context', '')
			];
		}

		return [
			'version' => $version,
			'communities' => Util::parseCommunities($this->getInput('communities', 'public')),
			'v3' => $v3
		];
	}

}
