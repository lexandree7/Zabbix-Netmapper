<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Target parsing. Accepted forms (comma / space / newline separated):
 *   10.0.0.0/24   10.0.0.1-10.0.0.50   10.0.0.1-50   10.0.0.7
 */
final class IpRange {

	/**
	 * @return array  [[start (int), end (int)], ...]
	 *
	 * @throws \InvalidArgumentException
	 */
	public static function parse(string $targets): array {
		$ranges = [];

		foreach (preg_split('/[\s,;]+/', trim($targets), -1, PREG_SPLIT_NO_EMPTY) as $item) {
			if (preg_match('/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/', $item, $m) && Util::isIpv4($m[1]) && $m[2] <= 32) {
				$bits = (int) $m[2];
				$mask = $bits == 0 ? 0 : (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF;
				$network = ip2long($m[1]) & $mask;
				$broadcast = $network | (~$mask & 0xFFFFFFFF);

				// Skip network and broadcast addresses for /0-/30.
				$ranges[] = ($bits <= 30) ? [$network + 1, $broadcast - 1] : [$network, $broadcast];
			}
			elseif (preg_match('/^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/', $item, $m)
					&& Util::isIpv4($m[1]) && Util::isIpv4($m[2])) {
				$ranges[] = [ip2long($m[1]), ip2long($m[2])];
			}
			elseif (preg_match('/^((\d+\.\d+\.\d+\.)(\d+))-(\d+)$/', $item, $m) && Util::isIpv4($m[1])
					&& $m[4] <= 255) {
				$ranges[] = [ip2long($m[1]), ip2long($m[2].$m[4])];
			}
			elseif (Util::isIpv4($item)) {
				$ranges[] = [ip2long($item), ip2long($item)];
			}
			else {
				throw new \InvalidArgumentException(sprintf(_('Invalid target "%1$s".'), $item));
			}

			if ($ranges[count($ranges) - 1][0] > $ranges[count($ranges) - 1][1]) {
				throw new \InvalidArgumentException(sprintf(_('Invalid target "%1$s".'), $item));
			}
		}

		if (!$ranges) {
			throw new \InvalidArgumentException(_('Enter a prefix, range or IP address.'));
		}

		return $ranges;
	}

	public static function count(array $ranges): int {
		$count = 0;

		foreach ($ranges as [$start, $end]) {
			$count += $end - $start + 1;
		}

		return $count;
	}

	/**
	 * Converts ranges into Zabbix discovery rule "iprange" syntax (a.b.c.d-e per /24 block).
	 */
	public static function toZabbixRange(array $ranges): string {
		$parts = [];

		foreach ($ranges as [$start, $end]) {
			while ($start <= $end) {
				$block_end = min($end, $start | 0xFF);
				$first = long2ip($start);

				$parts[] = ($start == $block_end)
					? $first
					: $first.'-'.($block_end & 0xFF);

				$start = $block_end + 1;
			}
		}

		return implode(',', $parts);
	}
}
