<?php declare(strict_types = 0);


namespace Modules\NetMapper\Includes;

/**
 * The SNMP request could not even be sent (no route, blocked by SELinux / firewall, ...).
 * Extends SnmpTimeoutException so existing "no answer" handling keeps working.
 */
class SnmpTransportException extends SnmpTimeoutException {

	/**
	 * Likely cause of a send error, for the user.
	 */
	public static function hint(int $errno): string {
		$unreachable = array_filter([
			defined('SOCKET_ENETUNREACH') ? SOCKET_ENETUNREACH : null,
			defined('SOCKET_EHOSTUNREACH') ? SOCKET_EHOSTUNREACH : null, 101, 113, 10051, 10065
		]);
		$denied = array_filter([
			defined('SOCKET_EACCES') ? SOCKET_EACCES : null, defined('SOCKET_EPERM') ? SOCKET_EPERM : null, 1, 13, 10013
		]);

		if (in_array($errno, $unreachable, true)) {
			return _('The Zabbix frontend server has no route to this address. If the network is only reachable '
				.'through a proxy, select the proxy as Source.'
			);
		}

		if (in_array($errno, $denied, true)) {
			return _('The frontend server blocked the request (SELinux: "setsebool -P httpd_can_network_connect on", '
				.'or a local firewall rule).'
			);
		}

		return '';
	}
}
