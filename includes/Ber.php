<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Minimal BER encoder/decoder for SNMPv1/v2c messages (RFC 1157 / RFC 3416).
 * Only read operations are implemented: GetRequest, GetNextRequest and GetBulkRequest.
 * SetRequest is intentionally NOT implemented.
 */
final class Ber {

	public const PDU_GET = 0xA0;
	public const PDU_GETNEXT = 0xA1;
	public const PDU_RESPONSE = 0xA2;
	public const PDU_GETBULK = 0xA5;
	public const PDU_REPORT = 0xA8;

	public const T_INTEGER = 0x02;
	public const T_OCTETS = 0x04;
	public const T_NULL = 0x05;
	public const T_OID = 0x06;
	public const T_IPADDR = 0x40;
	public const T_COUNTER32 = 0x41;
	public const T_GAUGE32 = 0x42;
	public const T_TIMETICKS = 0x43;
	public const T_OPAQUE = 0x44;
	public const T_COUNTER64 = 0x46;
	public const T_NOSUCHOBJECT = 0x80;
	public const T_NOSUCHINSTANCE = 0x81;
	public const T_ENDOFMIBVIEW = 0x82;

	public static function encodeRequest(int $version, string $community, int $pdu, int $reqid, int $a, int $b,
			array $oids): string {
		if (!in_array($pdu, [self::PDU_GET, self::PDU_GETNEXT, self::PDU_GETBULK], true)) {
			throw new \InvalidArgumentException('Only read-only SNMP PDUs are allowed.');
		}

		$varbinds = '';

		foreach ($oids as $oid) {
			$varbinds .= self::tlv(0x30, self::encodeOid($oid)."\x05\x00");
		}

		$body = self::encodeInt($reqid).self::encodeInt($a).self::encodeInt($b).self::tlv(0x30, $varbinds);

		return self::tlv(0x30, self::encodeInt($version).self::tlv(self::T_OCTETS, $community).self::tlv($pdu, $body));
	}

	/**
	 * @return array|null  ['reqid', 'error_status', 'error_index', 'varbinds' => [[oid, type, value], ...]]
	 */
	public static function decodeResponse(string $data): ?array {
		try {
			$pos = 0;
			$message = self::readTlv($data, $pos);

			if ($message === null || $message[0] != 0x30) {
				return null;
			}

			$content = $message[1];
			$pos = 0;
			$version = self::readTlv($content, $pos);
			$community = self::readTlv($content, $pos);
			$pdu = self::readTlv($content, $pos);

			if ($version === null || $community === null || $pdu === null
					|| ($pdu[0] != self::PDU_RESPONSE && $pdu[0] != self::PDU_REPORT)) {
				return null;
			}

			$body = $pdu[1];
			$pos = 0;
			$reqid = self::readTlv($body, $pos);
			$error_status = self::readTlv($body, $pos);
			$error_index = self::readTlv($body, $pos);
			$list = self::readTlv($body, $pos);

			if ($reqid === null || $error_status === null || $error_index === null || $list === null) {
				return null;
			}

			$varbinds = [];
			$pos = 0;

			while ($pos < strlen($list[1])) {
				$varbind = self::readTlv($list[1], $pos);

				if ($varbind === null) {
					break;
				}

				$vpos = 0;
				$oid = self::readTlv($varbind[1], $vpos);
				$value = self::readTlv($varbind[1], $vpos);

				if ($oid === null || $value === null || $oid[0] != self::T_OID) {
					continue;
				}

				$varbinds[] = [self::decodeOid($oid[1]), $value[0], self::decodeValue($value[0], $value[1])];
			}

			return [
				'reqid' => self::decodeInt($reqid[1]),
				'error_status' => self::decodeInt($error_status[1]),
				'error_index' => self::decodeInt($error_index[1]),
				'varbinds' => $varbinds
			];
		}
		catch (\Throwable $e) {
			return null;
		}
	}

	public static function compareOids(string $a, string $b): int {
		$x = explode('.', $a);
		$y = explode('.', $b);
		$n = min(count($x), count($y));

		for ($i = 0; $i < $n; $i++) {
			if ((int) $x[$i] != (int) $y[$i]) {
				return ((int) $x[$i] < (int) $y[$i]) ? -1 : 1;
			}
		}

		return count($x) <=> count($y);
	}

	private static function decodeValue(int $type, string $raw) {
		switch ($type) {
			case self::T_INTEGER:
				return self::decodeInt($raw);

			case self::T_COUNTER32:
			case self::T_GAUGE32:
			case self::T_TIMETICKS:
			case self::T_COUNTER64:
				return self::decodeUint($raw);

			case self::T_OID:
				return self::decodeOid($raw);

			case self::T_IPADDR:
				return strlen($raw) == 4 ? implode('.', array_map('ord', str_split($raw))) : bin2hex($raw);

			case self::T_NULL:
			case self::T_NOSUCHOBJECT:
			case self::T_NOSUCHINSTANCE:
			case self::T_ENDOFMIBVIEW:
				return null;

			default:
				return $raw;
		}
	}

	private static function readTlv(string $data, int &$pos): ?array {
		$end = strlen($data);

		if ($pos + 2 > $end) {
			return null;
		}

		$tag = ord($data[$pos++]);
		$len = ord($data[$pos++]);

		if ($len & 0x80) {
			$bytes = $len & 0x7F;

			if ($bytes == 0 || $bytes > 4 || $pos + $bytes > $end) {
				return null;
			}

			$len = 0;

			for ($i = 0; $i < $bytes; $i++) {
				$len = ($len << 8) | ord($data[$pos++]);
			}
		}

		if ($pos + $len > $end) {
			return null;
		}

		$value = (string) substr($data, $pos, $len);
		$pos += $len;

		return [$tag, $value];
	}

	private static function tlv(int $tag, string $value): string {
		return chr($tag).self::encodeLength(strlen($value)).$value;
	}

	private static function encodeLength(int $len): string {
		if ($len < 0x80) {
			return chr($len);
		}

		$out = '';

		while ($len > 0) {
			$out = chr($len & 0xFF).$out;
			$len >>= 8;
		}

		return chr(0x80 | strlen($out)).$out;
	}

	private static function encodeInt(int $value): string {
		if ($value < 0) {
			throw new \InvalidArgumentException('Negative integers are not used by this client.');
		}

		$out = '';

		do {
			$out = chr($value & 0xFF).$out;
			$value >>= 8;
		} while ($value > 0);

		if (ord($out[0]) & 0x80) {
			$out = "\x00".$out;
		}

		return self::tlv(self::T_INTEGER, $out);
	}

	private static function decodeInt(string $raw): int {
		$len = strlen($raw);

		if ($len == 0) {
			return 0;
		}

		$value = 0;

		for ($i = 0; $i < $len && $i < 8; $i++) {
			$value = ($value << 8) | ord($raw[$i]);
		}

		if ($len < 8 && (ord($raw[0]) & 0x80)) {
			$value -= (1 << (8 * $len));
		}

		return $value;
	}

	/**
	 * @return int|float
	 */
	private static function decodeUint(string $raw) {
		$value = 0;

		foreach (str_split($raw) as $char) {
			$value = $value * 256 + ord($char);
		}

		return $value;
	}

	private static function encodeOid(string $oid): string {
		$parts = array_map('intval', explode('.', trim($oid, '.')));

		if (count($parts) < 2) {
			throw new \InvalidArgumentException('Invalid OID: '.$oid);
		}

		$out = self::base128(40 * $parts[0] + $parts[1]);

		for ($i = 2, $n = count($parts); $i < $n; $i++) {
			$out .= self::base128($parts[$i]);
		}

		return self::tlv(self::T_OID, $out);
	}

	private static function base128(int $value): string {
		$out = chr($value & 0x7F);
		$value >>= 7;

		while ($value > 0) {
			$out = chr(0x80 | ($value & 0x7F)).$out;
			$value >>= 7;
		}

		return $out;
	}

	private static function decodeOid(string $raw): string {
		$parts = [];
		$value = 0;
		$first = true;

		foreach (str_split($raw) as $char) {
			$byte = ord($char);
			$value = ($value << 7) | ($byte & 0x7F);

			if ($byte & 0x80) {
				continue;
			}

			if ($first) {
				if ($value < 80) {
					$parts[] = intdiv($value, 40);
					$parts[] = $value % 40;
				}
				else {
					$parts[] = 2;
					$parts[] = $value - 80;
				}

				$first = false;
			}
			else {
				$parts[] = $value;
			}

			$value = 0;
		}

		return implode('.', $parts);
	}
}
