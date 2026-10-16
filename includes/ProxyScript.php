<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

use API,
	CWebUser;

/**
 * Scan through a Zabbix proxy with a global script (remote command) executed on the proxy:
 * script.execute on a host monitored by the selected proxy runs the command on that proxy.
 *
 * The command is fixed (fping); the only variable part is {MANUALINPUT}, which the Zabbix server validates against
 * a regular expression that accepts nothing but space separated IPv4 addresses before executing anything.
 */
final class ProxyScript {

	public const SCRIPT_NAME = 'NetMapper: ping scan';
	public const MAX_IPS_PER_RUN = 64;

	private const OCTET = '(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])';

	public static function validator(): string {
		$ip = '('.self::OCTET.'\.){3}'.self::OCTET;

		return '^'.$ip.'( '.$ip.'){0,'.(self::MAX_IPS_PER_RUN - 1).'}$';
	}

	public static function command(): string {
		// fping exits with 1 when some targets are unreachable; the scan result is the list of alive targets (-a).
		return '/usr/sbin/fping -a -q -r 1 -t 500 {MANUALINPUT} 2>/dev/null; exit 0';
	}

	/**
	 * @throws ProxyScriptSetupException  when the script does not exist or is not usable
	 */
	public static function findScript(): array {
		return self::findScriptByName(self::SCRIPT_NAME);
	}

	/**
	 * Finds a global script of this module and checks that it is a safe "Zabbix server (proxy)" script with a
	 * validated manual input.
	 *
	 * @throws ProxyScriptSetupException
	 */
	public static function findScriptByName(string $name): array {
		$scripts = API::Script()->get([
			'output' => ['scriptid', 'name', 'type', 'execute_on', 'scope', 'command', 'manualinput',
				'manualinput_validator_type'
			],
			'filter' => ['name' => $name]
		]);

		if (!$scripts) {
			throw new ProxyScriptSetupException(sprintf(
				_('Global script "%1$s" not found (or you have no permission to use it).'), $name
			));
		}

		$script = $scripts[0];
		$problems = [];

		if ($script['type'] != ZBX_SCRIPT_TYPE_CUSTOM_SCRIPT) {
			$problems[] = _('type must be "Script"');
		}

		if ($script['execute_on'] != ZBX_SCRIPT_EXECUTE_ON_PROXY) {
			$problems[] = _('"Execute on" must be "Zabbix server (proxy)"');
		}

		if (!($script['scope'] & ZBX_SCRIPT_SCOPE_HOST)) {
			$problems[] = _('scope must be "Manual host action"');
		}

		if ($script['manualinput'] != ZBX_SCRIPT_MANUALINPUT_ENABLED
				|| $script['manualinput_validator_type'] != ZBX_SCRIPT_MANUALINPUT_TYPE_STRING
				|| strpos($script['command'], '{MANUALINPUT}') === false) {
			$problems[] = _('it must use "{MANUALINPUT}" with a regular expression validator');
		}

		if ($problems) {
			throw new ProxyScriptSetupException(sprintf(_('Global script "%1$s" is misconfigured: %2$s.'),
				$name, implode('; ', $problems)
			));
		}

		return $script;
	}

	/**
	 * Creates the script with the safe default configuration (Super admin only).
	 */
	public static function createScript(): string {
		return self::createScriptFromDefinition([
			'name' => self::SCRIPT_NAME,
			'type' => ZBX_SCRIPT_TYPE_CUSTOM_SCRIPT,
			'scope' => ZBX_SCRIPT_SCOPE_HOST,
			'execute_on' => ZBX_SCRIPT_EXECUTE_ON_PROXY,
			'command' => self::command(),
			'description' => 'Used by the Network mapper module: ICMP liveness scan (fping) from the proxy that '
				.'monitors the selected host. The input accepts only space separated IPv4 addresses.',
			'menu_path' => 'NetMapper',
			'host_access' => PERM_READ,
			'timeout' => '30s',
			'manualinput' => ZBX_SCRIPT_MANUALINPUT_ENABLED,
			'manualinput_prompt' => 'IPv4 addresses (space separated)',
			'manualinput_validator_type' => ZBX_SCRIPT_MANUALINPUT_TYPE_STRING,
			'manualinput_validator' => self::validator(),
			'manualinput_default_value' => '127.0.0.1'
		]);
	}

	/**
	 * Creates a global script of this module (Super admin only).
	 */
	public static function createScriptFromDefinition(array $script): string {
		if (CWebUser::getType() != USER_TYPE_SUPER_ADMIN) {
			throw new \RuntimeException(_('Only Super admin users can create global scripts.'));
		}

		$result = API::Script()->create([$script]);

		if (!$result) {
			throw new \RuntimeException(self::apiError(_('Cannot create global script.')));
		}

		return (string) reset($result['scriptids']);
	}

	/**
	 * A host monitored by the proxy (directly or as the proxy currently assigned by a proxy group).
	 */
	public static function findHost(string $proxyid): array {
		$options = [
			'output' => ['hostid', 'name', 'status'],
			'sortfield' => 'status',
			'limit' => 1
		];

		$hosts = API::Host()->get($options + ['proxyids' => [$proxyid]]);

		if (!$hosts) {
			$hosts = API::Host()->get($options + ['filter' => ['assigned_proxyid' => $proxyid]]);
		}

		if (!$hosts) {
			throw new \RuntimeException(_('No host monitored by the selected proxy is visible to you. '
				.'The remote command runs in the context of a host monitored by the proxy.'
			));
		}

		return $hosts[0];
	}

	/**
	 * @param string[] $ips
	 *
	 * @return string[]  alive IPs
	 */
	public static function ping(string $scriptid, string $hostid, array $ips): array {
		$alive = [];

		foreach (array_chunk(array_values(array_filter($ips, [Util::class, 'isIpv4'])), self::MAX_IPS_PER_RUN) as $chunk) {
			$result = API::Script()->execute([
				'scriptid' => $scriptid,
				'hostid' => $hostid,
				'manualinput' => implode(' ', $chunk)
			]);

			if (!$result) {
				throw new \RuntimeException(self::apiError(_('Cannot execute remote command on the proxy.')));
			}

			foreach (preg_split('/\s+/', (string) $result['value'], -1, PREG_SPLIT_NO_EMPTY) as $token) {
				if (in_array($token, $chunk, true)) {
					$alive[$token] = $token;
				}
			}
		}

		return array_values($alive);
	}

	public static function apiError(string $default): string {
		if (function_exists('get_and_clear_messages')) {
			$messages = array_column(get_and_clear_messages(), 'message');

			if ($messages) {
				return implode(' ', $messages);
			}
		}

		return $default;
	}
}
