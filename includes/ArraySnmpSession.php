<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * SNMP "session" answered from values collected earlier (e.g. walk[] items executed by a proxy).
 * Never touches the network.
 */
class ArraySnmpSession extends SnmpSession {

	/** @var array  oid (no leading dot) => value */
	private array $values;

	public function __construct(string $ip, array $values) {
		$this->ip = $ip;
		$this->values = $values;
		$this->timeout_ms = 0;
		$this->retries = 0;
	}

	public function get(array $oids): array {
		$result = [];

		foreach ($oids as $oid) {
			$result[$oid] = $this->values[$oid] ?? null;
		}

		return $result;
	}

	public function walk(string $base_oid, int $max_rows = 20000): array {
		$prefix = trim($base_oid, '.').'.';
		$result = [];

		foreach ($this->values as $oid => $value) {
			if (strpos((string) $oid, $prefix) === 0) {
				$result[(string) $oid] = $value;
			}
		}

		uksort($result, [Ber::class, 'compareOids']);

		return array_slice($result, 0, $max_rows, true);
	}
}
