<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * SNMPv3 session based on the PHP "snmp" extension (php-snmp), used only when the extension is available.
 */
class SnmpV3Session extends SnmpSession {

	private const LEVELS = ['noAuthNoPriv', 'authNoPriv', 'authPriv'];

	private \SNMP $snmp;

	public function __construct(string $ip, ?array $v3, int $timeout_ms, int $retries) {
		if (!class_exists('SNMP')) {
			throw new \RuntimeException(_('SNMPv3 requires the PHP "snmp" extension on the Zabbix frontend server.'));
		}

		if ($v3 === null || $v3['user'] === '') {
			throw new \RuntimeException(_('SNMPv3 security name is required.'));
		}

		$this->ip = $ip;
		$this->timeout_ms = $timeout_ms;
		$this->retries = $retries;

		$this->snmp = new \SNMP(\SNMP::VERSION_3, $ip, $v3['user'], $timeout_ms * 1000, $retries);
		$level = self::LEVELS[$v3['level']] ?? 'authPriv';

		$this->snmp->setSecurity($level,
			$level !== 'noAuthNoPriv' ? $v3['auth_proto'] : '',
			$level !== 'noAuthNoPriv' ? $v3['auth_pass'] : '',
			$level === 'authPriv' ? $v3['priv_proto'] : '',
			$level === 'authPriv' ? $v3['priv_pass'] : '',
			$v3['context']
		);

		$this->snmp->valueretrieval = SNMP_VALUE_PLAIN;
		$this->snmp->oid_output_format = SNMP_OID_OUTPUT_NUMERIC;
		$this->snmp->quick_print = true;
		$this->snmp->exceptions_enabled = \SNMP::ERRNO_TIMEOUT;
	}

	public function __destruct() {
		@$this->snmp->close();
	}

	public function get(array $oids): array {
		$result = array_fill_keys($oids, null);

		try {
			$values = @$this->snmp->get($oids);
		}
		catch (\SNMPException $e) {
			throw new SnmpTimeoutException($e->getMessage());
		}

		if (is_array($values)) {
			foreach ($values as $oid => $value) {
				$oid = ltrim($oid, '.');

				if (array_key_exists($oid, $result)) {
					$result[$oid] = $value;
				}
			}
		}

		return $result;
	}

	public function walk(string $base_oid, int $max_rows = 20000): array {
		try {
			$values = @$this->snmp->walk(trim($base_oid, '.'), false, 25, $max_rows);
		}
		catch (\SNMPException $e) {
			throw new SnmpTimeoutException($e->getMessage());
		}

		$result = [];

		if (is_array($values)) {
			foreach ($values as $oid => $value) {
				$result[ltrim($oid, '.')] = $value;
			}
		}

		return $result;
	}
}
