<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Read-only SNMP session (GET / WALK only).
 */
abstract class SnmpSession {

	protected string $ip;
	protected int $timeout_ms;
	protected int $retries;

	public static function create(string $ip, array $credentials, int $community_index = 0): self {
		$timeout = Config::get('snmp_timeout_ms');
		$retries = Config::get('snmp_retries');

		if ($credentials['version'] == 3) {
			return new SnmpV3Session($ip, $credentials['v3'], $timeout, $retries);
		}

		$community = $credentials['communities'][$community_index] ?? ($credentials['communities'][0] ?? 'public');

		return new SnmpV12Session($ip, (int) $credentials['version'], $community, $timeout, $retries);
	}

	/**
	 * @param string[] $oids
	 *
	 * @return array  oid => value (null when not available)
	 */
	abstract public function get(array $oids): array;

	/**
	 * @return array  full oid => value
	 */
	abstract public function walk(string $base_oid, int $max_rows = 20000): array;

	/**
	 * Same as walk(), but keys are the OID suffix after $base_oid (the table index).
	 */
	public function walkIndex(string $base_oid, int $max_rows = 20000): array {
		$result = [];
		$prefix_len = strlen($base_oid) + 1;

		foreach ($this->walk($base_oid, $max_rows) as $oid => $value) {
			$result[substr($oid, $prefix_len)] = $value;
		}

		return $result;
	}

	public function getIp(): string {
		return $this->ip;
	}

	/**
	 * Returns a session using a different community string (Cisco "community@vlan" indexing). v1/v2c only.
	 */
	public function withCommunity(string $community): ?self {
		return null;
	}

	public function getCommunity(): ?string {
		return null;
	}
}
