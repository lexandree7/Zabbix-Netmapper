<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

use APP;

/**
 * Access to the module options stored in the database ("config" section of manifest.json).
 */
final class Config {

	public const MODULE_ID = 'amg_netmapper';

	private const DEFAULTS = [
		'max_targets' => 4096,
		'scan_chunk_size' => 64,
		'tcp_timeout_ms' => 800,
		'tcp_concurrency' => 64,
		'snmp_timeout_ms' => 1500,
		'snmp_retries' => 1,
		'fping_path' => '/usr/sbin/fping',
		'tcp_ports_minimal' => '22,23,80,443',
		'tcp_ports_standard' => '21,22,23,80,102,135,443,445,502,554,1911,3389,4840,8080,8443,9100,20000,44818',
		'http_timeout_ms' => 3000
	];

	public static function get(string $name) {
		$default = self::DEFAULTS[$name] ?? null;

		try {
			$module = APP::ModuleManager()->getModule(self::MODULE_ID);
		}
		catch (\Throwable $e) {
			$module = null;
		}

		$value = $module !== null ? $module->getOption($name, $default) : $default;

		return is_int($default) ? (int) $value : $value;
	}

	/**
	 * @return int[]
	 */
	public static function getPorts(string $profile): array {
		$list = self::get($profile === 'minimal' ? 'tcp_ports_minimal' : 'tcp_ports_standard');
		$ports = [];

		foreach (explode(',', (string) $list) as $port) {
			$port = (int) trim($port);

			if ($port > 0 && $port < 65536) {
				$ports[$port] = $port;
			}
		}

		return array_values($ports);
	}
}
