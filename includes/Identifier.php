<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * Collects identification data about a single device. All operations are read-only:
 * HTTP GET, banner reading, SNMP GET/WALK, EtherNet/IP ListIdentity.
 */
final class Identifier {

	private const OID_IF_PHYS_ADDRESS = '1.3.6.1.2.1.2.2.1.6';
	private const OID_IP_AD_ENT_IFINDEX = '1.3.6.1.2.1.4.20.1.2';
	private const OID_BRIDGE_ADDRESS = '1.3.6.1.2.1.17.1.1.0';
	private const OID_BRIDGE_NUM_PORTS = '1.3.6.1.2.1.17.1.2.0';
	private const OID_LLDP_LOC_CHASSIS_SUBTYPE = '1.0.8802.1.1.2.1.3.1.0';
	private const OID_LLDP_LOC_CHASSIS_ID = '1.0.8802.1.1.2.1.3.2.0';
	private const OID_LLDP_LOC_SYSNAME = '1.0.8802.1.1.2.1.3.3.0';
	private const OID_ENT_PHYSICAL = '1.3.6.1.2.1.47.1.1.1.1';

	private array $log = [];

	public function getLog(): array {
		return $this->log;
	}

	/**
	 * @param array      $ports  known open TCP ports (from scan), empty = probe the default ones
	 * @param array      $snmp   SNMP credentials (see BaseJsonController::getSnmpCredentials())
	 */
	public function identify(string $ip, array $ports, array $snmp, ?int $community_index, bool $use_snmp): array {
		$result = [
			'ip' => $ip,
			'ports' => $ports,
			'snmp' => null,
			'http' => null,
			'https' => null,
			'ssh' => null,
			'telnet' => null,
			'enip' => null,
			'macs' => [],
			'chassis_id' => null,
			'lldp_sysname' => '',
			'bridge_mac' => null,
			'bridge_ports' => 0,
			'lldp' => false
		];

		if (!$ports) {
			$probe = Scanner::tcpProbe([$ip], [22, 23, 80, 443, 44818], Config::get('tcp_timeout_ms'), 8);
			$ports = $probe[$ip]['open'] ?? [];
			$result['ports'] = $ports;
		}

		$texts = [];

		// SNMP.
		if ($use_snmp) {
			$result['snmp'] = $this->snmpDetails($ip, $snmp, $community_index, $result);

			if ($result['snmp'] !== null) {
				$texts[] = $result['snmp']['entity_model'] ?? '';
			}
		}

		// HTTP / HTTPS.
		if (in_array(80, $ports) || in_array(8080, $ports)) {
			$result['http'] = $this->http($ip, in_array(80, $ports) ? 80 : 8080, false);
		}

		if (in_array(443, $ports) || in_array(8443, $ports)) {
			$result['https'] = $this->http($ip, in_array(443, $ports) ? 443 : 8443, true);
		}

		foreach (['http', 'https'] as $proto) {
			if ($result[$proto] !== null) {
				$texts[] = $result[$proto]['title'].' '.$result[$proto]['server'].' '.$result[$proto]['realm'].' '
					.($result[$proto]['certificate'] ?? '');
			}
		}

		// SSH / Telnet banners.
		if (in_array(22, $ports)) {
			$result['ssh'] = ['banner' => $this->sshBanner($ip)];
			$texts[] = $result['ssh']['banner'];
		}

		if (in_array(23, $ports)) {
			$result['telnet'] = ['banner' => $this->telnetBanner($ip)];
			$texts[] = $result['telnet']['banner'];
		}

		// EtherNet/IP.
		if (in_array(44818, $ports)) {
			$result['enip'] = $this->enipListIdentity($ip);
		}

		$snmp_system = $result['snmp']['system'] ?? [];
		$mac = $result['macs'][0] ?? (Util::localArpTable()[$ip] ?? null);

		if ($mac !== null && !in_array($mac, $result['macs'])) {
			$result['macs'][] = $mac;
		}

		$classification = Fingerprint::classify([
			'sysdescr' => $snmp_system['sysdescr'] ?? '',
			'sysobjectid' => $snmp_system['sysobjectid'] ?? '',
			'sysservices' => $snmp_system['sysservices'] ?? 0,
			'bridge_ports' => $result['bridge_ports'],
			'texts' => $texts,
			'ports' => $ports,
			'enip' => $result['enip'],
			'mac' => $mac
		]);

		$result['classification'] = $classification;
		$result['model'] = $this->guessModel($result);
		$result['sysname'] = $snmp_system['sysname'] ?? '';

		return $result;
	}

	private function snmpDetails(string $ip, array $credentials, ?int $community_index, array &$result): ?array {
		$indexes = ($credentials['version'] == 3)
			? [0]
			: ($community_index !== null ? [$community_index] : array_keys($credentials['communities']));
		$session = null;
		$values = null;

		foreach ($indexes as $index) {
			try {
				$session = SnmpSession::create($ip, $credentials, $index);
				$values = $session->get(array_merge(array_values(SnmpProbe::SYSTEM_OIDS), [
					self::OID_BRIDGE_ADDRESS, self::OID_BRIDGE_NUM_PORTS, self::OID_LLDP_LOC_CHASSIS_SUBTYPE,
					self::OID_LLDP_LOC_CHASSIS_ID, self::OID_LLDP_LOC_SYSNAME
				]));

				if ($values[SnmpProbe::SYSTEM_OIDS['descr']] !== null || $values[SnmpProbe::SYSTEM_OIDS['name']] !== null
						|| $values[SnmpProbe::SYSTEM_OIDS['objectid']] !== null) {
					$community_index = $index;
					break;
				}

				$values = null;
			}
			catch (SnmpTimeoutException $e) {
				$values = null;
			}
			catch (\Throwable $e) {
				$this->log[] = 'SNMP: '.$e->getMessage();

				return null;
			}
		}

		if ($values === null) {
			$this->log[] = sprintf('SNMP: no response from %s.', $ip);

			return null;
		}

		$this->log[] = sprintf('SNMP v%s: response from %s.', $credentials['version'] == 2 ? '2c' : $credentials['version'],
			$ip
		);

		$system = [];

		foreach (SnmpProbe::SYSTEM_OIDS as $key => $oid) {
			$system[$key] = $values[$oid];
		}

		$details = [
			'version' => $credentials['version'],
			'community_index' => ($credentials['version'] == 3) ? null : $community_index,
			'system' => SnmpProbe::formatSystem($system)
		];

		$result['bridge_mac'] = Util::macFromSnmp($values[self::OID_BRIDGE_ADDRESS]);
		$result['bridge_ports'] = (int) $values[self::OID_BRIDGE_NUM_PORTS];
		$result['lldp'] = $values[self::OID_LLDP_LOC_CHASSIS_ID] !== null;
		$result['lldp_sysname'] = Util::text($values[self::OID_LLDP_LOC_SYSNAME], 255);

		if ($values[self::OID_LLDP_LOC_CHASSIS_ID] !== null) {
			$result['chassis_id'] = ((int) $values[self::OID_LLDP_LOC_CHASSIS_SUBTYPE] == 4)
				? Util::macFromSnmp($values[self::OID_LLDP_LOC_CHASSIS_ID])
				: Util::text($values[self::OID_LLDP_LOC_CHASSIS_ID], 255);
		}

		try {
			// MAC address of the interface that owns the probed IP comes first.
			$if_index = $session->get([self::OID_IP_AD_ENT_IFINDEX.'.'.$ip])[self::OID_IP_AD_ENT_IFINDEX.'.'.$ip];
			$macs = $session->walkIndex(self::OID_IF_PHYS_ADDRESS, 2000);

			if ($if_index !== null && array_key_exists((string) $if_index, $macs)) {
				$primary = Util::macFromSnmp($macs[(string) $if_index]);

				if ($primary !== null) {
					$result['macs'][] = $primary;
				}
			}

			foreach ($macs as $value) {
				$mac = Util::macFromSnmp($value);

				if ($mac !== null && !in_array($mac, $result['macs'])) {
					$result['macs'][] = $mac;
				}
			}

			if ($result['bridge_mac'] !== null && !in_array($result['bridge_mac'], $result['macs'])) {
				$result['macs'][] = $result['bridge_mac'];
			}

			$result['macs'] = array_slice($result['macs'], 0, 512);

			// ENTITY-MIB: model, serial, firmware of the first physical entity that reports them.
			$model = $session->walkIndex(self::OID_ENT_PHYSICAL.'.13', 50);
			$serial = $session->walkIndex(self::OID_ENT_PHYSICAL.'.11', 50);
			$software = $session->walkIndex(self::OID_ENT_PHYSICAL.'.10', 50);

			foreach ($model as $index => $value) {
				if (trim((string) $value) !== '') {
					$details['entity_model'] = Util::text($value, 128);
					$details['entity_serial'] = Util::text($serial[$index] ?? '', 128);
					$details['entity_software'] = Util::text($software[$index] ?? '', 128);
					break;
				}
			}
		}
		catch (\Throwable $e) {
			$this->log[] = 'SNMP: '.$e->getMessage();
		}

		return $details;
	}

	/**
	 * Anonymous HTTP(S) GET "/" (same-host redirects are followed). No credentials are ever sent.
	 */
	private function http(string $ip, int $port, bool $tls): ?array {
		$timeout = Config::get('http_timeout_ms') / 1000;
		$path = '/';
		$response = null;

		for ($i = 0; $i < 3; $i++) {
			$response = $this->httpGet($ip, $port, $tls, $path, $timeout);

			if ($response === null) {
				return null;
			}

			if (in_array($response['status'], [301, 302, 303, 307, 308]) && $response['location'] !== '') {
				$location = parse_url($response['location']);

				if ($location === false || (isset($location['host']) && $location['host'] !== $ip)) {
					break;
				}

				$path = ($location['path'] ?? '/').(isset($location['query']) ? '?'.$location['query'] : '');
				continue;
			}

			break;
		}

		$this->log[] = sprintf('%s:%d: HTTP %d %s', $tls ? 'https' : 'http', $port, $response['status'],
			$response['title']
		);

		unset($response['www_authenticate'], $response['location']);

		$response['port'] = $port;

		return $response;
	}

	private function httpGet(string $ip, int $port, bool $tls, string $path, float $timeout): ?array {
		$stream = Scanner::connect($ip, $port, $timeout, $tls);

		if ($stream === null) {
			return null;
		}

		$certificate = '';

		if ($tls) {
			$params = stream_context_get_params($stream);
			$cert = $params['options']['ssl']['peer_certificate'] ?? null;

			if ($cert) {
				$parsed = @openssl_x509_parse($cert);

				if (is_array($parsed)) {
					$subject = $parsed['subject'] ?? [];
					$certificate = trim(implode(' ', array_filter([
						is_array($subject['CN'] ?? null) ? implode(' ', $subject['CN']) : ($subject['CN'] ?? ''),
						is_array($subject['O'] ?? null) ? implode(' ', $subject['O']) : ($subject['O'] ?? ''),
						is_array($subject['OU'] ?? null) ? implode(' ', $subject['OU']) : ($subject['OU'] ?? '')
					])));
				}
			}
		}

		$request = "GET ".$path." HTTP/1.0\r\nHost: ".$ip."\r\nUser-Agent: Zabbix-NetMapper/1.0\r\nAccept: */*\r\n"
			."Connection: close\r\n\r\n";

		@fwrite($stream, $request);

		$data = '';
		$deadline = microtime(true) + $timeout;

		while (!feof($stream) && strlen($data) < 65536 && microtime(true) < $deadline) {
			$chunk = @fread($stream, 8192);

			if ($chunk === false) {
				break;
			}

			if ($chunk === '') {
				$meta = stream_get_meta_data($stream);

				if ($meta['timed_out']) {
					break;
				}

				usleep(10000);
				continue;
			}

			$data .= $chunk;
		}

		fclose($stream);

		if (!preg_match('/^HTTP\/\d(?:\.\d)?\s+(\d{3})/', $data, $m)) {
			return $data !== '' ? [
				'status' => 0, 'server' => '', 'title' => Util::text(substr($data, 0, 80), 80), 'realm' => '',
				'certificate' => $certificate, 'www_authenticate' => '', 'location' => ''
			] : null;
		}

		[$head, $body] = array_pad(explode("\r\n\r\n", $data, 2), 2, '');
		$headers = [];

		foreach (explode("\r\n", $head) as $line) {
			if (strpos($line, ':') !== false) {
				[$name, $value] = explode(':', $line, 2);
				$headers[strtolower(trim($name))] = trim($value);
			}
		}

		$title = '';

		if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $body, $t)) {
			$title = html_entity_decode(trim(preg_replace('/\s+/', ' ', strip_tags($t[1]))), ENT_QUOTES | ENT_HTML5);
		}

		$realm = '';

		if (preg_match('/realm="([^"]*)"/i', $headers['www-authenticate'] ?? '', $r)) {
			$realm = $r[1];
		}

		return [
			'status' => (int) $m[1],
			'server' => Util::text($headers['server'] ?? '', 128),
			'title' => Util::text($title, 160),
			'realm' => Util::text($realm, 128),
			'certificate' => Util::text($certificate, 255),
			'www_authenticate' => $headers['www-authenticate'] ?? '',
			'location' => $headers['location'] ?? ''
		];
	}

	private function sshBanner(string $ip): string {
		$stream = Scanner::connect($ip, 22, 3);

		if ($stream === null) {
			return '';
		}

		stream_set_timeout($stream, 3);
		$banner = (string) @fgets($stream, 256);
		fclose($stream);

		$banner = Util::text(trim($banner), 255);
		$this->log[] = 'SSH banner: '.$banner;

		return $banner;
	}

	/**
	 * Reads the Telnet greeting (refusing every option negotiation) without logging in.
	 */
	private function telnetBanner(string $ip): string {
		$stream = Scanner::connect($ip, 23, 3);

		if ($stream === null) {
			return '';
		}

		stream_set_blocking($stream, false);
		$text = '';
		$deadline = microtime(true) + 2.5;

		while (microtime(true) < $deadline && strlen($text) < 2048) {
			$chunk = @fread($stream, 1024);

			if ($chunk === false || ($chunk === '' && feof($stream))) {
				break;
			}

			if ($chunk === '') {
				usleep(50000);
				continue;
			}

			[$clean, $reply] = self::telnetRefuseOptions($chunk);
			$text .= $clean;

			if ($reply !== '') {
				@fwrite($stream, $reply);
			}

			if (preg_match('/(login|user(name)?|password)\s*:\s*$/i', $text)) {
				break;
			}
		}

		fclose($stream);

		$banner = Util::text(trim(Util::stripAnsi($text)), 512);
		$this->log[] = 'Telnet banner: '.preg_replace('/\s+/', ' ', mb_substr($banner, 0, 120));

		return $banner;
	}

	/**
	 * Strips Telnet IAC sequences and builds a reply that refuses every option (DO -> WONT, WILL -> DONT).
	 *
	 * @return array  [printable data, reply bytes]
	 */
	private static function telnetRefuseOptions(string $data): array {
		$clean = '';
		$reply = '';
		$len = strlen($data);

		for ($i = 0; $i < $len; $i++) {
			$byte = ord($data[$i]);

			if ($byte != 255) {
				$clean .= $data[$i];
				continue;
			}

			$command = ($i + 1 < $len) ? ord($data[$i + 1]) : 0;

			if ($command == 255) {
				$clean .= "\xFF";
				$i++;
			}
			elseif ($command >= 251 && $command <= 254 && $i + 2 < $len) {
				$option = $data[$i + 2];

				if ($command == 253) {
					$reply .= "\xFF\xFC".$option;
				}
				elseif ($command == 251) {
					$reply .= "\xFF\xFE".$option;
				}

				$i += 2;
			}
			elseif ($command == 250) {
				$end = strpos($data, "\xFF\xF0", $i + 2);
				$i = ($end === false) ? $len : $end + 1;
			}
			else {
				$i++;
			}
		}

		return [$clean, $reply];
	}

	/**
	 * EtherNet/IP "ListIdentity" (encapsulation command 0x63) - a read-only discovery request.
	 */
	private function enipListIdentity(string $ip): ?array {
		$stream = Scanner::connect($ip, 44818, 3);

		if ($stream === null) {
			return null;
		}

		stream_set_timeout($stream, 3);
		@fwrite($stream, pack('vvVVa8V', 0x63, 0, 0, 0, 'netmappr', 0));

		$data = '';
		$deadline = microtime(true) + 3;

		while (strlen($data) < 24 && microtime(true) < $deadline && !feof($stream)) {
			$data .= (string) @fread($stream, 1024);
		}

		if (strlen($data) >= 24) {
			$length = unpack('v', substr($data, 2, 2))[1];

			while (strlen($data) < 24 + $length && microtime(true) < $deadline && !feof($stream)) {
				$data .= (string) @fread($stream, 1024);
			}
		}

		fclose($stream);

		// Header (24) + item count (2) + item type (2) + item length (2) + version (2) + socket address (16).
		if (strlen($data) < 24 + 6 + 2 + 16 + 15) {
			return null;
		}

		$offset = 24 + 6 + 2 + 16;
		$identity = unpack('vvendor/vtype/vproduct/Cmajor/Cminor/vstatus/Vserial/Clen', substr($data, $offset, 15));
		$name = substr($data, $offset + 15, $identity['len']);

		$enip = [
			'vendor_id' => $identity['vendor'],
			'device_type' => $identity['type'],
			'device_type_name' => Fingerprint::ENIP_DEVICE_TYPES[$identity['type']] ?? sprintf('0x%02X', $identity['type']),
			'product_code' => $identity['product'],
			'revision' => $identity['major'].'.'.$identity['minor'],
			'serial' => sprintf('%08X', $identity['serial']),
			'product_name' => Util::text($name, 128)
		];

		$this->log[] = sprintf('EtherNet/IP: %s (vendor %d, %s, rev %s)', $enip['product_name'], $enip['vendor_id'],
			$enip['device_type_name'], $enip['revision']
		);

		return $enip;
	}


	private function guessModel(array $result): string {
		if (!empty($result['snmp']['entity_model'])) {
			return $result['snmp']['entity_model'];
		}

		if (!empty($result['enip']['product_name'])) {
			return $result['enip']['product_name'];
		}

		$descr = $result['snmp']['system']['sysdescr'] ?? '';

		if ($descr !== '') {
			return mb_substr(strtok($descr, "\n"), 0, 80);
		}

		return $result['https']['title'] ?? ($result['http']['title'] ?? '');
	}
}
