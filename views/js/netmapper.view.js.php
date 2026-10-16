<?php declare(strict_types = 0);
/**
 * @var CView $this
 */
?>

<script>
const view = new class {

	init(config) {
		this.config = config;
		this.T = <?= json_encode([
			'scan' => _('Scan'),
			'identify' => _('Identify'),
			'find_neighbors' => _('Find neighbors (SNMP)'),
			'cli_paste' => _('Neighbors from CLI output'),
			'add_host' => _('Add host'),
			'remove' => _('Remove from map'),
			'pin' => _('Pin position'),
			'unpin' => _('Unpin position'),
			'not_in_zabbix' => _('Not monitored by Zabbix'),
			'in_zabbix' => _('Zabbix host'),
			'ports' => _('Ports'),
			'neighbors' => _('Neighbors'),
			'cancel' => _('Cancel'),
			'close' => _('Close'),
			'parse' => _('Parse output'),
			'save' => _('Save'),
			'confirm_clear' => _('Remove all devices and connections from the map?'),
			'clear' => _('Clear'),
			'session_error' => _('Unexpected server response (session expired or access denied). Reload the page.'),
			'no_targets' => _('Enter a prefix, range or IP address.'),
			'too_many' => _('Too many addresses'),
			'proxy_note' => _('Scan runs on the proxy through a temporary discovery rule. Identification and neighbor search run from the frontend server.'),
			'cli_note' => _('The module never connects to device CLIs. Log in yourself with an unprivileged (read-only) account, run the commands below and paste the output. Pasted text is parsed in memory and not stored.'),
			'copy' => _('Copy'),
			'copied' => _('Copied'),
			'host_name' => _('Host name'),
			'visible_name' => _('Visible name'),
			'host_groups' => _('Host groups'),
			'templates' => _('Templates'),
			'filter' => _('Filter'),
			'interfaces' => _('Interfaces'),
			'description' => _('Description'),
			'map_name' => _('Map name'),
			'map_saved' => _('Map created'),
			'open' => _('Open'),
			'problems' => _('Problems'),
			'latest_data' => _('Latest data'),
			'configuration' => _('Configuration')
		]) ?>;

		this.nodes = new Map();
		this.links = new Map();
		this.mac_index = new Map();
		this.chassis_index = new Map();
		this.ip_alias = new Map();
		this.arp = new Map();
		this.selected = null;
		this.busy = false;
		this.abort = false;
		this.proxy_rule = null;
		this.view_box = {x: -100, y: -100, w: 1600, h: 900};

		this.buildSvg();
		this.bindToolbar();
		this.restore();
		this.render();
		this.fit();
	}

	// ---------------------------------------------------------------- helpers

	t(key) {
		return this.T[key] ?? key;
	}

	el(tag, attrs = {}, children = []) {
		const svg_tags = ['svg', 'g', 'line', 'circle', 'rect', 'path', 'text', 'use', 'symbol', 'defs', 'title', 'tspan'];
		const node = svg_tags.includes(tag)
			? document.createElementNS('http://www.w3.org/2000/svg', tag)
			: document.createElement(tag);

		for (const [key, value] of Object.entries(attrs)) {
			if (value === null || value === undefined || value === false) {
				continue;
			}

			if (key === 'text') {
				node.textContent = value;
			}
			else if (key.startsWith('on')) {
				node.addEventListener(key.substring(2), value);
			}
			else {
				node.setAttribute(key, value === true ? '' : value);
			}
		}

		for (const child of [].concat(children)) {
			if (child !== null && child !== undefined && child !== false) {
				node.append(child instanceof Node ? child : document.createTextNode(String(child)));
			}
		}

		return node;
	}

	log(message, level = 'info') {
		const log = document.getElementById('nm-log');
		const time = new Date().toLocaleTimeString();

		log.append(this.el('div', {class: 'nm-log-' + level}, `[${time}] ${message}`));

		while (log.children.length > 500) {
			log.firstChild.remove();
		}

		log.scrollTop = log.scrollHeight;
	}

	status(text) {
		document.getElementById('nm-status').textContent = text;
	}

	value(id) {
		const element = document.getElementById(id);

		if (element === null) {
			return '';
		}

		if (element.type === 'checkbox') {
			return element.checked ? '1' : '0';
		}

		return element.value ?? '';
	}

	static portKey(name) {
		let key = String(name ?? '').trim().toLowerCase();
		const hirschmann = key.match(/module\s*:?\s*(\d+)\s*[,\-]?\s*port\s*:?\s*(\d+)/);

		if (hirschmann) {
			return hirschmann[1] + '/' + hirschmann[2];
		}

		key = key.replace(/\s+/g, '');

		const prefixes = [
			['hundredgigabitethernet', 'hu'], ['hundredgige', 'hu'], ['fortygigabitethernet', 'fo'],
			['twentyfivegigabitethernet', 'twe'], ['twentyfivegige', 'twe'], ['tengigabitethernet', 'te'],
			['tengige', 'te'], ['ten', 'te'], ['gigabitethernet', 'gi'], ['gige', 'gi'], ['gig', 'gi'],
			['fastethernet', 'fa'], ['fas', 'fa'], ['ethernet', 'eth'], ['port-channel', 'po'], ['portchannel', 'po'],
			['interface', ''], ['port', '']
		];

		for (const [long, short] of prefixes) {
			if (key.startsWith(long)) {
				return short + key.substring(long.length);
			}
		}

		return key;
	}

	static ipToInt(ip) {
		return ip.split('.').reduce((acc, octet) => acc * 256 + Number(octet), 0);
	}

	static intToIp(value) {
		return [24, 16, 8, 0].map(shift => Math.floor(value / 2 ** shift) % 256).join('.');
	}

	static isIp(ip) {
		return /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(ip);
	}

	/**
	 * Expands "10.0.0.0/24, 10.0.1.1-10.0.1.9, 10.0.2.1-20, 10.0.3.4" (same syntax as IpRange.php).
	 */
	expandTargets(text) {
		const ips = [];
		const max = this.config.max_targets;

		for (const item of text.split(/[\s,;]+/).filter(Boolean)) {
			let start, end, match;

			if ((match = item.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/)) && view.constructor.isIp(match[1])
					&& Number(match[2]) <= 32) {
				const bits = Number(match[2]);
				const size = 2 ** (32 - bits);
				const network = Math.floor(view.constructor.ipToInt(match[1]) / size) * size;

				[start, end] = bits <= 30 ? [network + 1, network + size - 2] : [network, network + size - 1];
			}
			else if ((match = item.match(/^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/))
					&& view.constructor.isIp(match[1]) && view.constructor.isIp(match[2])) {
				[start, end] = [view.constructor.ipToInt(match[1]), view.constructor.ipToInt(match[2])];
			}
			else if ((match = item.match(/^((\d+\.\d+\.\d+\.)(\d+))-(\d+)$/)) && view.constructor.isIp(match[1])
					&& Number(match[4]) <= 255) {
				[start, end] = [view.constructor.ipToInt(match[1]), view.constructor.ipToInt(match[2] + match[4])];
			}
			else if (view.constructor.isIp(item)) {
				start = end = view.constructor.ipToInt(item);
			}
			else {
				throw new Error(`Invalid target "${item}".`);
			}

			if (start > end) {
				throw new Error(`Invalid target "${item}".`);
			}

			if (ips.length + (end - start + 1) > max) {
				throw new Error(`${this.t('too_many')} (max ${max}).`);
			}

			for (let value = start; value <= end; value++) {
				ips.push(view.constructor.intToIp(value));
			}
		}

		if (!ips.length) {
			throw new Error(this.t('no_targets'));
		}

		return [...new Set(ips)];
	}

	// ---------------------------------------------------------------- server API

	snmpParams() {
		const params = {
			snmp_version: this.value('nm-snmp-version'),
			communities: this.value('nm-communities')
		};

		if (params.snmp_version === '3') {
			// SNMPv3 secrets are only read from the form at request time; they are never stored by the page.
			Object.assign(params, {
				v3_user: this.value('nm-v3-user'),
				v3_level: this.value('nm-v3-level'),
				v3_auth_proto: this.value('nm-v3-auth-proto'),
				v3_auth_pass: this.value('nm-v3-auth-pass'),
				v3_priv_proto: this.value('nm-v3-priv-proto'),
				v3_priv_pass: this.value('nm-v3-priv-pass'),
				v3_context: this.value('nm-v3-context')
			});
		}

		return params;
	}

	async post(action, params) {
		const body = new URLSearchParams();

		for (const [key, value] of Object.entries(params)) {
			if (Array.isArray(value)) {
				value.forEach(item => body.append(key + '[]', item));
			}
			else if (value !== null && value !== undefined) {
				body.append(key, value);
			}
		}

		body.append(this.config.csrf_field, this.config.csrf[action]);

		const response = await fetch('zabbix.php?action=' + encodeURIComponent(action), {
			method: 'POST',
			headers: {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'},
			body
		});

		let data;

		try {
			data = await response.json();
		}
		catch (e) {
			throw new Error(this.t('session_error'));
		}

		if (data === null || typeof data !== 'object') {
			throw new Error(this.t('session_error'));
		}

		if (data.error) {
			const error = new Error(data.error);

			error.data = data;
			throw error;
		}

		return data;
	}

	// ---------------------------------------------------------------- toolbar

	bindToolbar() {
		document.getElementById('nm-scan').addEventListener('click', () => this.scan());
		document.getElementById('nm-stop').addEventListener('click', () => {
			this.abort = true;
			this.status('Stopping…');
		});
		document.getElementById('nm-explore-all').addEventListener('click', () => this.exploreAll());
		document.getElementById('nm-layout').addEventListener('click', () => {
			this.autoLayout();
			this.render();
			this.fit();
			this.persist();
		});
		document.getElementById('nm-fit').addEventListener('click', () => this.fit());
		document.getElementById('nm-export').addEventListener('click', () => this.exportJson());
		document.getElementById('nm-import').addEventListener('click', () => this.importJson());
		document.getElementById('nm-save-map').addEventListener('click', () => this.saveZabbixMap());
		document.getElementById('nm-clear').addEventListener('click', () => this.confirmClear());
		document.getElementById('nm-remember').addEventListener('change', () => this.saveSettings());
		document.getElementById('nm-communities').addEventListener('change', () => {
			if (this.value('nm-remember') === '1') {
				this.saveSettings();
			}
		});

		const version = document.getElementById('nm-snmp-version');
		const toggle = () => {
			const v3 = this.value('nm-snmp-version') === '3';

			document.querySelectorAll('.netmapper .nm-snmp-v3').forEach(node => node.hidden = !v3);
			document.querySelectorAll('.netmapper .nm-snmp-v12').forEach(node => node.hidden = v3);
		};

		version.addEventListener('change', toggle);
		toggle();

		const source_toggle = () => {
			const proxy = this.value('nm-source') !== 'server';

			document.querySelectorAll('.netmapper .nm-proxy-only').forEach(node => node.hidden = !proxy);

			return proxy;
		};

		document.getElementById('nm-source').addEventListener('change', () => {
			if (source_toggle()) {
				this.log(this.t('proxy_note'));
			}
		});
		source_toggle();
	}

	setBusy(busy) {
		this.busy = busy;
		this.abort = false;
		document.getElementById('nm-scan').disabled = busy;
		document.getElementById('nm-explore-all').disabled = busy;
		document.getElementById('nm-stop').disabled = !busy;
	}

	async saveSettings() {
		try {
			await this.post('netmapper.settings.update', {
				communities: this.value('nm-communities'),
				remember: this.value('nm-remember')
			});
			this.log(this.value('nm-remember') === '1'
				? 'SNMP communities saved in your user profile.'
				: 'Saved SNMP communities removed from your user profile.'
			);
		}
		catch (e) {
			this.log(e.message, 'error');
		}
	}

	probeParams() {
		return {
			probe_icmp: this.value('nm-probe-icmp'),
			probe_tcp: this.value('nm-probe-tcp'),
			probe_snmp: this.value('nm-probe-snmp'),
			port_profile: this.value('nm-port-profile')
		};
	}

	// ---------------------------------------------------------------- scan

	async scan() {
		if (this.busy) {
			return;
		}

		const targets = this.value('nm-targets').trim();
		const source = this.value('nm-source');

		let ips;

		try {
			ips = this.expandTargets(targets);
		}
		catch (e) {
			this.log(e.message, 'error');

			return;
		}

		if (this.value('nm-remember') === '1') {
			this.saveSettings();
		}

		this.setBusy(true);

		try {
			if (source === 'server') {
				await this.scanFromServer(ips);
			}
			else if (this.value('nm-proxy-method') === 'script') {
				await this.scanFromServer(ips, source);
			}
			else {
				await this.scanFromProxy(source, targets);
			}
		}
		catch (e) {
			this.log(e.message, 'error');

			if (e.data?.setup_required) {
				this.openScriptSetup(e.data);
			}
		}
		finally {
			this.setBusy(false);
			this.status('');
			this.persist();
		}
	}

	/**
	 * Chunked scan. Without proxyid the probes run on the frontend server, with proxyid the
	 * "NetMapper: ping scan" global script runs fping on that proxy.
	 */
	async scanFromServer(ips, proxyid = null) {
		const chunk = this.config.chunk_size;
		const chunks = [];

		for (let i = 0; i < ips.length; i += chunk) {
			chunks.push(ips.slice(i, i + chunk));
		}

		this.log(proxyid === null
			? `Scanning ${ips.length} addresses from the frontend server (${chunks.length} requests).`
			: `Scanning ${ips.length} addresses with fping on the proxy (remote command, ${chunks.length} requests). `
				+ 'Only ICMP is probed on the proxy.'
		);

		let setup_error = null;

		let done = 0;
		let found = 0;
		const worker = async () => {
			while (chunks.length && !this.abort) {
				const ips_chunk = chunks.shift();

				try {
					const data = await this.post('netmapper.scan', proxyid === null
						? {source: 'server', ips: ips_chunk, ...this.probeParams(), ...this.snmpParams()}
						: {source: 'proxy_script', proxyid, ips: ips_chunk}
					);

					if (data.executed_via && done === 0) {
						this.log(`Remote command "${data.executed_via.script}" executed on the proxy of host `
							+ `"${data.executed_via.host}" (hostid ${data.executed_via.hostid}).`
						);
					}

					found += data.results.length;
					this.addScanResults(data.results);

					if (proxyid === null && !data.fping && this.value('nm-probe-icmp') === '1' && done === 0) {
						this.log('fping is not available on the frontend server: ICMP probe skipped (TCP/SNMP/ARP still used).',
							'warning'
						);
					}
				}
				catch (e) {
					if (e.data?.setup_required) {
						setup_error = e;
						chunks.length = 0;
						break;
					}

					this.log(`${ips_chunk[0]}…: ${e.message}`, 'error');
				}

				done += ips_chunk.length;
				this.status(`${done}/${ips.length} scanned, ${found} active`);
			}
		};

		// Two parallel requests from the server (gentle with OT networks), one at a time through a proxy.
		await Promise.all(proxyid === null ? [worker(), worker()] : [worker()]);

		if (setup_error !== null) {
			throw setup_error;
		}
		this.log(`Scan finished: ${found} active addresses.` + (this.abort ? ' (stopped)' : ''));
	}

	async scanFromProxy(proxyid, targets) {
		this.log(this.t('proxy_note'));

		const start = await this.post('netmapper.scan', {
			source: 'proxy', step: 'start', proxyid, targets, ...this.probeParams(), ...this.snmpParams()
		});

		if (start.snmpv3_skipped) {
			this.log('SNMPv3 secrets are never written into discovery rules: the proxy scan uses ICMP/TCP only.',
				'warning'
			);
		}

		const druleid = start.druleid;
		const started = Date.now();
		let last_count = -1;
		let stable = 0;

		this.log(`Temporary discovery rule ${druleid} created. Waiting for proxy results…`);
		this.log(`Check it in Monitoring → Discovery: zabbix.php?action=discovery.view&filter_set=1&filter_druleids%5B%5D=${druleid}`);

		let polls = 0;
		let last_diag = '';

		try {
			while (!this.abort && Date.now() - started < 20 * 60000) {
				await new Promise(resolve => setTimeout(resolve, 10000));

				const data = await this.post('netmapper.scan', {
					source: 'proxy', step: 'poll', druleid, ...this.snmpParams()
				});

				this.logProxyDiagnostics(data.diagnostics, polls++, last_diag);
				last_diag = JSON.stringify([data.diagnostics?.dhosts_total, data.diagnostics?.dservices_total]);
				this.addScanResults(data.results);
				this.status(`Proxy: ${data.results.length} active (${Math.round((Date.now() - started) / 1000)} s)`);

				stable = (data.results.length === last_count && last_count > 0) ? stable + 1 : 0;
				last_count = data.results.length;

				if (stable >= 6) {
					break;
				}
			}
		}
		finally {
			await this.post('netmapper.scan', {source: 'proxy', step: 'stop', druleid}).catch(e => this.log(e.message, 'error'));
			this.log(`Proxy scan finished: ${Math.max(last_count, 0)} active addresses. Temporary rule removed.`);
		}
	}

	/**
	 * Logs where the proxy scan really runs: rule, proxy state, raw discovery counters (including "down" results).
	 */
	logProxyDiagnostics(diag, poll, last_diag) {
		if (!diag) {
			return;
		}

		const counters = JSON.stringify([diag.dhosts_total, diag.dservices_total]);

		// Full report on the first poll, then when counters change or every minute.
		if (poll > 0 && counters === last_diag && poll % 6 !== 0) {
			return;
		}

		const proxy = diag.proxy;

		if (poll === 0) {
			this.log(`Rule "${diag.rule_name}" (id ${diag.druleid}), range ${diag.iprange}, ${diag.dchecks} checks, `
				+ (diag.rule_enabled ? 'enabled' : 'DISABLED') + '.'
			);
		}

		if (!proxy) {
			this.log('The discovery rule is not assigned to any proxy (or the proxy is not visible to you).', 'error');
		}
		else {
			const seen = proxy.last_seen_sec === null ? 'never' : `${proxy.last_seen_sec} s ago`;

			this.log(`Proxy "${proxy.name}" (${proxy.mode}): ${proxy.state}, last seen ${seen}, compatibility `
				+ `${proxy.compatibility}. Discovery records: ${diag.dhosts_total} hosts (${diag.dhosts_up} up), `
				+ `${diag.dservices_total} services (${diag.dservices_up} up).`
			);

			if (proxy.state === 'offline' || proxy.last_seen_sec === null || proxy.last_seen_sec > 120) {
				this.log(`Proxy "${proxy.name}" is not communicating with the server: the rule will not run.`, 'error');
			}

			if (proxy.compatibility === 'outdated' || proxy.compatibility === 'unsupported') {
				this.log(`Proxy version is ${proxy.compatibility}: an outdated proxy does not receive configuration `
					+ 'updates (new discovery rules) from the server.', 'error'
				);
			}
		}

		if (poll >= 6 && diag.dhosts_total === 0) {
			this.log('No discovery records after 1 minute. Check the proxy log (discovery manager / discoverer), '
				+ 'fping on the proxy (ICMP) and firewall rules from the proxy to the targets.', 'warning'
			);
		}
	}

	/**
	 * The global script used for proxy scans is missing or misconfigured.
	 */
	openScriptSetup(data) {
		const body = [
			this.el('p', {text: data.error}),
			this.el('p', {text: 'The proxy scan runs a fixed fping command on the proxy. The only variable part is '
				+ '{MANUALINPUT}, validated by the Zabbix server with the regular expression below (space separated IPv4 '
				+ 'addresses only).'
			}),
			this.el('table', {class: 'nm-props'}, [
				['Name', data.script.name], ['Type', 'Script'], ['Scope', 'Manual host action'],
				['Execute on', 'Zabbix server (proxy)'], ['Commands', data.script.command],
				['Advanced → Manual input', 'Enabled, input type: String'], ['Input validation rule', data.script.validator],
				['Timeout', '30s']
			].map(([key, value]) => this.el('tr', {}, [this.el('th', {text: key}), this.el('td', {}, this.el('code', {text: value}))]))),
			this.el('p', {class: 'nm-hint', text: 'Requirements on the proxy: EnableRemoteCommands=1 in zabbix_proxy.conf '
				+ '(restart the proxy) and fping installed as /usr/sbin/fping.'
			})
		];

		const buttons = [[this.t('close'), close => close()]];

		if (data.can_create) {
			buttons.unshift(['Create script', async close => {
				try {
					const result = await this.post('netmapper.scan', {source: 'proxy_script', step: 'setup'});

					close();
					this.log(`Global script "${data.script.name}" created (id ${result.scriptid}). Run the scan again.`);
				}
				catch (e) {
					this.log(e.message, 'error');
				}
			}, true]);
		}
		else {
			body.push(this.el('p', {class: 'nm-hint', text: 'Ask a Super admin to create it (Alerts → Scripts).'}));
		}

		this.openModal('Proxy scan: remote command setup', body, buttons);
	}

	addScanResults(results) {
		const fresh = [];

		for (const result of results) {
			let node = this.nodeByIp(result.ip);

			if (!node) {
				node = this.createNode('ip:' + result.ip, {ip: result.ip});
				fresh.push(node);
			}

			node.alive = true;
			node.ports = [...new Set([...(node.ports ?? []), ...(result.ports ?? [])])].sort((a, b) => a - b);
			node.reasons = result.reasons;

			if (result.snmp) {
				node.snmp = {
					version: result.snmp.version,
					community_index: result.snmp.community_index,
					system: result.snmp.system
				};
				node.sysname = result.snmp.system.sysname || node.sysname;
			}

			if (result.mac) {
				this.addMacs(node, [result.mac]);
				node = this.nodes.get(node.id) ?? node;
			}

			if (result.host) {
				node.host = result.host;
			}

			this.applyClassification(node, result.classification);
			this.absorbDuplicates(node);
		}

		this.placeGrid(fresh.filter(node => this.nodes.has(node.id)));
		this.render();
	}

	applyClassification(node, classification) {
		if (!classification) {
			return;
		}

		if (classification.vendor) {
			node.vendor = classification.vendor;
			node.vendor_name = classification.vendor_name;
		}

		if (classification.type && (classification.type !== 'unknown' || !node.type)) {
			node.type = classification.type;
		}

		node.network_device = node.network_device || classification.network_device;
	}

	// ---------------------------------------------------------------- nodes, identity, links

	createNode(id, props = {}) {
		const node = {
			id, ip: null, label: '', sysname: '', type: 'unknown', vendor: null, vendor_name: '', model: '',
			ports: [], macs: [], host: null, snmp: null, x: 0, y: 0, fixed: false, explored: false,
			network_device: false, info: {}, port_roles: [], chassis_ids: [], lldp_names: [], port_aliases: {},
			extra_ips: [], ...props
		};

		this.nodes.set(id, node);

		for (const chassis of node.chassis_ids) {
			this.chassis_index.set(chassis, id);
		}

		return node;
	}

	nodeLabel(node) {
		return node.host?.name || node.sysname || node.label || node.ip || node.macs[0] || node.id;
	}

	/**
	 * A node known only through LLDP/CDP or a MAC table entry (not scanned, not identified).
	 */
	static isProvisional(node) {
		return (node.id.startsWith('lldp:') || node.id.startsWith('mac:')) && !node.alive && !node.identified
			&& !node.explored;
	}

	static isMac(value) {
		return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(value);
	}

	/**
	 * Normalized LLDP chassis ID: MAC addresses in any notation become "aa:bb:cc:dd:ee:ff".
	 */
	static chassisKey(value) {
		const text = String(value ?? '').trim().toLowerCase();

		if (text === '') {
			return '';
		}

		if (/^([0-9a-f]{1,2}[:\- ]){5}[0-9a-f]{1,2}$/.test(text)) {
			return text.split(/[:\- ]/).map(part => part.padStart(2, '0')).join(':');
		}

		if (/^[0-9a-f]{4}[.\-][0-9a-f]{4}[.\-][0-9a-f]{4}$/.test(text) || /^[0-9a-f]{12}$/.test(text)) {
			return text.replace(/[^0-9a-f]/g, '').match(/../g).join(':');
		}

		return text;
	}

	/**
	 * Device names are equal when identical (case-insensitive), or when one is the host part of the other FQDN
	 * ("sw1" vs "sw1.plant.local"). Names containing dots for other reasons are only compared exactly.
	 */
	static sameName(a, b) {
		a = String(a ?? '').trim().toLowerCase();
		b = String(b ?? '').trim().toLowerCase();

		if (a === '' || b === '') {
			return false;
		}

		if (a === b) {
			return true;
		}

		const fqdn = /^[a-z0-9_\-]+(\.[a-z0-9_\-]+)*\.[a-z]{2,}$/;

		return (!a.includes('.') && fqdn.test(b) && b.split('.')[0] === a)
			|| (!b.includes('.') && fqdn.test(a) && a.split('.')[0] === b);
	}

	nodeNames(node) {
		return [node.sysname, node.host?.host, node.host?.name, ...(node.lldp_names ?? [])].filter(Boolean);
	}

	nodeByIp(ip) {
		if (!ip) {
			return null;
		}

		return this.nodes.get('ip:' + ip) ?? this.nodes.get(this.ip_alias.get(ip)) ?? null;
	}

	/**
	 * Registers how the device identifies itself to its neighbors (LLDP chassis ID, LLDP system name, advertised
	 * port IDs) and merges provisional duplicates created earlier from neighbor tables.
	 */
	registerIdentity(node, local) {
		if (!local) {
			return node;
		}

		const chassis = view.constructor.chassisKey(local.chassis_id);

		if (chassis && !node.chassis_ids.includes(chassis)) {
			node.chassis_ids.push(chassis);
		}

		for (const name of [local.lldp_sysname, local.sysname]) {
			if (name && !node.lldp_names.includes(name)) {
				node.lldp_names.push(name);
			}
		}

		if (local.sysname && !node.sysname) {
			node.sysname = local.sysname;
		}

		let aliases_changed = false;

		for (const port of local.port_ids ?? []) {
			for (const alias of [port.id, port.desc]) {
				const key = view.constructor.portKey(alias);

				if (key && key !== view.constructor.portKey(port.name) && node.port_aliases[key] !== port.name) {
					node.port_aliases[key] = port.name;
					aliases_changed = true;
				}
			}
		}

		this.addMacs(node, [local.bridge_mac, view.constructor.isMac(chassis) ? chassis : null].filter(Boolean));
		node = this.nodes.get(node.id) ?? node;

		for (const id of node.chassis_ids) {
			this.chassis_index.set(id, node.id);
		}

		this.absorbDuplicates(node);

		if (aliases_changed) {
			this.normalizeLinks();
		}

		return node;
	}

	/**
	 * Merges provisional nodes that are the same device as "node" (same chassis ID, MAC or name).
	 */
	absorbDuplicates(node) {
		if (!this.nodes.has(node.id) || view.constructor.isProvisional(node)) {
			return;
		}

		const names = this.nodeNames(node);

		for (const other of [...this.nodes.values()]) {
			if (other === node || !this.nodes.has(other.id)) {
				continue;
			}

			const same_chassis = other.chassis_ids.some(id => node.chassis_ids.includes(id) || node.macs.includes(id));
			const same_mac = view.constructor.isProvisional(other) && other.macs.some(mac => node.macs.includes(mac));
			const same_name = this.nodeNames(other).some(a => names.some(b => view.constructor.sameName(a, b)));

			if (!same_chassis && !same_mac && !same_name) {
				continue;
			}

			if (view.constructor.isProvisional(other) || !other.ip) {
				this.log(`"${this.nodeLabel(other)}" is the same device as "${this.nodeLabel(node)}" `
					+ `(${same_chassis ? 'chassis ID' : same_mac ? 'MAC address' : 'name'}): merged.`
				);
				this.mergeNode(other, node);
			}
			else if (same_chassis && other.ip !== node.ip) {
				this.log(`${node.ip} and ${other.ip} report the same chassis ID: same device with two addresses? `
					+ 'Use "Merge with" in the side panel to combine them.', 'warning'
				);
			}
		}
	}

	addMacs(node, macs) {
		for (const mac of macs) {
			if (!mac || mac === '00:00:00:00:00:00') {
				continue;
			}

			if (!node.macs.includes(mac)) {
				node.macs.push(mac);
			}

			const owner_id = this.mac_index.get(mac) ?? this.chassis_index.get(mac);

			// A provisional node (known only by MAC / LLDP) is merged into the identified one.
			if (owner_id && owner_id !== node.id && this.nodes.has(owner_id)) {
				const owner = this.nodes.get(owner_id);

				if (view.constructor.isProvisional(owner)) {
					this.mergeNode(owner, node);
				}
				else if (view.constructor.isProvisional(node)) {
					this.mergeNode(node, owner);

					return;
				}
			}

			this.mac_index.set(mac, node.id);
		}
	}

	mergeNode(from, into) {
		if (from === into || !this.nodes.has(from.id) || !this.nodes.has(into.id)) {
			return;
		}

		// The node with an IP address (scanned / identified) always survives.
		if (!into.ip && from.ip) {
			[from, into] = [into, from];
		}

		this.nodes.delete(from.id);

		for (const mac of from.macs) {
			if (!into.macs.includes(mac)) {
				into.macs.push(mac);
			}

			this.mac_index.set(mac, into.id);
		}

		for (const chassis of from.chassis_ids) {
			if (!into.chassis_ids.includes(chassis)) {
				into.chassis_ids.push(chassis);
			}

			this.chassis_index.set(chassis, into.id);
		}

		for (const name of [from.sysname, ...from.lldp_names]) {
			if (name && !into.lldp_names.includes(name)) {
				into.lldp_names.push(name);
			}
		}

		for (const ip of [from.ip, ...from.extra_ips]) {
			if (ip && ip !== into.ip && !into.extra_ips.includes(ip)) {
				into.extra_ips.push(ip);
				this.ip_alias.set(ip, into.id);
			}
		}

		Object.assign(into.port_aliases, from.port_aliases, {...into.port_aliases});
		into.sysname = into.sysname || from.sysname;
		into.vendor = into.vendor || from.vendor;
		into.vendor_name = into.vendor_name || from.vendor_name;
		into.host = into.host || from.host;
		into.snmp = into.snmp || from.snmp;
		into.network_device = into.network_device || from.network_device;
		into.explored = into.explored || from.explored;
		into.info.lldp = into.info.lldp || from.info.lldp;

		if (into.type === 'unknown') {
			into.type = from.type;
		}

		for (const link of [...this.links.values()]) {
			if (link.a === from.id || link.b === from.id) {
				this.links.delete(link.key);

				const a = link.a === from.id ? into.id : link.a;
				const b = link.b === from.id ? into.id : link.b;

				if (a !== b) {
					this.upsertLink(a, link.a_port, b, link.b_port, link.protocol);
				}
			}
		}

		if (this.selected === from.id) {
			this.selected = into.id;
		}
	}

	/**
	 * Ports known by their local name on a node (from its own neighbor/MAC tables).
	 */
	knownPorts(node) {
		const names = new Set((node.port_roles ?? []).map(port => port.port));

		for (const link of this.links.values()) {
			if (link.a === node.id && link.a_port) {
				names.add(link.a_port);
			}

			if (link.b === node.id && link.b_port) {
				names.add(link.b_port);
			}
		}

		Object.values(node.port_aliases ?? {}).forEach(name => names.add(name));

		return [...names].filter(name => !/^port[\s\-_]*\d+$/i.test(name));
	}

	/**
	 * Local interface name for a port ID advertised through LLDP (e.g. "port-008" -> "Fa0/8").
	 */
	canonicalPort(id, port) {
		if (!port) {
			return '';
		}

		const node = this.nodes.get(id);

		if (!node) {
			return port;
		}

		const alias = node.port_aliases?.[view.constructor.portKey(port)];

		if (alias) {
			return alias;
		}

		// "port-008" / "Port 8": the only known interface whose name ends with that number.
		const match = String(port).trim().match(/^port[\s\-_]*0*(\d+)$/i);

		if (match) {
			const hits = this.knownPorts(node).filter(name => {
				const tail = name.match(/[^\d](\d+)$/);

				return tail !== null && Number(tail[1]) === Number(match[1]);
			});

			if (hits.length === 1) {
				return hits[0];
			}
		}

		return port;
	}

	/**
	 * Re-applies port canonicalization and deduplication to every link.
	 */
	normalizeLinks() {
		const links = [...this.links.values()];

		this.links.clear();

		for (const link of links) {
			this.upsertLink(link.a, link.a_port, link.b, link.b_port, link.protocol);
		}
	}

	upsertLink(a, a_port, b, b_port, protocol) {
		if (a === b) {
			return;
		}

		a_port = this.canonicalPort(a, a_port);
		b_port = this.canonicalPort(b, b_port);

		// Normalize direction: the lower id is always "a".
		if (a > b) {
			[a, b, a_port, b_port] = [b, a, b_port, a_port];
		}

		const ak = view.constructor.portKey(a_port);
		const bk = view.constructor.portKey(b_port);
		const priority = {lldp: 3, cdp: 3, mndp: 2, mac: 1};
		const generic = name => /^port[\s\-_]*\d+$/i.test(name);
		const precise = protocol !== 'mac';

		for (const link of this.links.values()) {
			if (link.a !== a || link.b !== b) {
				continue;
			}

			const la = view.constructor.portKey(link.a_port);
			const lb = view.constructor.portKey(link.b_port);
			const a_same = ak !== '' && ak === la;
			const b_same = bk !== '' && bk === lb;
			const a_free = !ak || !la || a_same;
			const b_free = !bk || !lb || b_same;

			// Same pair of devices: same link when the ports are compatible, or when both are LLDP/CDP links that
			// share one of the ports (a port connects to a single port of the same neighbor).
			if ((a_free && b_free) || (precise && link.protocol !== 'mac' && (a_same || b_same))) {
				if (!link.a_port || (generic(link.a_port) && a_port && !generic(a_port))) {
					link.a_port = a_port || link.a_port;
				}

				if (!link.b_port || (generic(link.b_port) && b_port && !generic(b_port))) {
					link.b_port = b_port || link.b_port;
				}

				if ((priority[protocol] ?? 0) > (priority[link.protocol] ?? 0)) {
					link.protocol = protocol;
				}

				return link;
			}
		}

		// A switch port can hold only one physical link: a precise (LLDP/CDP) link replaces a MAC based one.
		if (precise) {
			for (const link of [...this.links.values()]) {
				if (link.protocol !== 'mac') {
					continue;
				}

				if ((link.a === a && ak && view.constructor.portKey(link.a_port) === ak)
						|| (link.b === a && ak && view.constructor.portKey(link.b_port) === ak)
						|| (link.a === b && bk && view.constructor.portKey(link.a_port) === bk)
						|| (link.b === b && bk && view.constructor.portKey(link.b_port) === bk)) {
					this.links.delete(link.key);
				}
			}
		}

		const key = `${a}|${ak}|${b}|${bk}|${Math.random().toString(36).slice(2, 8)}`;
		const link = {key, a, b, a_port: a_port || '', b_port: b_port || '', protocol};

		this.links.set(key, link);

		return link;
	}

	/**
	 * Manual fallback: the user states that two nodes are the same device.
	 */
	mergeManually(node, other_id) {
		const other = this.nodes.get(other_id);

		if (!other || other === node) {
			return;
		}

		this.log(`"${this.nodeLabel(other)}" merged into "${this.nodeLabel(node)}" (manual).`);
		this.mergeNode(other, node);
		this.normalizeLinks();
		this.render();
		this.renderPanel();
		this.persist();
	}

	removeNode(id) {
		for (const link of [...this.links.values()]) {
			if (link.a === id || link.b === id) {
				this.links.delete(link.key);
			}
		}

		for (const index of [this.mac_index, this.chassis_index, this.ip_alias]) {
			for (const [key, owner] of [...index.entries()]) {
				if (owner === id) {
					index.delete(key);
				}
			}
		}

		this.nodes.delete(id);

		if (this.selected === id) {
			this.selected = null;
		}

		this.render();
		this.renderPanel();
		this.persist();
	}

	// ---------------------------------------------------------------- identify

	async identify(node) {
		if (!node.ip) {
			return;
		}

		this.status(`Identifying ${node.ip}…`);

		try {
			const data = await this.post('netmapper.identify', {
				ip: node.ip,
				ports: node.ports,
				community_index: node.snmp?.community_index ?? null,
				probe_snmp: this.value('nm-probe-snmp'),
				...this.snmpParams()
			});

			node.alive = true;
			node.ports = data.ports;
			node.model = data.model || node.model;
			node.sysname = data.sysname || node.sysname;
			node.host = data.host ?? node.host;
			node.identified = true;
			node.info = {
				...node.info,
				http: data.http, https: data.https, ssh: data.ssh, telnet: data.telnet, enip: data.enip,
				chassis_id: data.chassis_id, bridge_ports: data.bridge_ports, lldp: data.lldp
			};

			if (data.snmp) {
				node.snmp = data.snmp;
			}

			this.applyClassification(node, data.classification);

			if (data.bridge_ports > 0 || data.lldp) {
				node.network_device = node.network_device || data.classification.type === 'switch'
					|| data.classification.type === 'router';
			}

			this.addMacs(node, data.macs);
			node = this.registerIdentity(this.nodes.get(node.id) ?? node, {
				chassis_id: data.chassis_id, lldp_sysname: data.lldp_sysname, sysname: data.sysname,
				bridge_mac: data.bridge_mac, port_ids: []
			});
			(data.log ?? []).forEach(line => this.log(`${node.ip}: ${line}`));
			this.log(`${node.ip}: ${node.vendor_name || 'unknown vendor'}, ${node.type}${node.model ? ', ' + node.model : ''}.`);
		}
		catch (e) {
			this.log(`${node.ip}: ${e.message}`, 'error');
		}
		finally {
			this.status('');
			this.render();
			this.renderPanel();
			this.persist();
		}
	}

	// ---------------------------------------------------------------- neighbors

	async findNeighbors(node) {
		if (!node.ip) {
			return;
		}

		this.status(`Collecting neighbors of ${this.nodeLabel(node)}…`);

		try {
			const params = {
				ip: node.ip,
				vendor: node.vendor ?? '',
				with_fdb: 1,
				...this.snmpParams()
			};

			if (node.snmp && node.snmp.community_index !== null && node.snmp.community_index !== undefined) {
				params.community_index = node.snmp.community_index;
			}

			const proxyid = this.value('nm-source');
			const data = proxyid === 'server'
				? await this.post('netmapper.neighbors', params)
				: await this.findNeighborsViaProxy(node, proxyid, params);

			if (data.community_index !== null && data.community_index !== undefined) {
				node.snmp = {...(node.snmp ?? {version: Number(this.value('nm-snmp-version'))}),
					community_index: data.community_index
				};
			}

			this.applyNeighbors(node, data);
		}
		catch (e) {
			this.log(`${node.ip}: ${e.message}`, 'error');
		}
		finally {
			this.status('');
		}
	}

	/**
	 * Collects through the selected proxy: a temporary host with walk[] items is created, polled until the proxy
	 * has delivered every subtree, and always removed at the end.
	 */
	async findNeighborsViaProxy(node, proxyid, params) {
		const start = await this.post('netmapper.neighbors', {...params, proxyid, step: 'start'});
		const started = Date.now();
		let data = null;

		this.log(`${node.ip}: temporary host ${start.hostid} created on the proxy; waiting for the SNMP walks `
			+ '(the proxy must first receive the configuration, usually under 1-2 minutes).'
		);

		try {
			while (!this.abort && Date.now() - started < 10 * 60000) {
				await new Promise(resolve => setTimeout(resolve, 5000));

				const poll = await this.post('netmapper.neighbors', {ip: node.ip, vendor: params.vendor, proxyid,
					hostid: start.hostid, step: 'poll'
				});

				this.status(`${node.ip}: proxy collected ${poll.collected ?? '…'}/${poll.total ?? '…'} subtrees `
					+ `(${Math.round((Date.now() - started) / 1000)} s)`
				);

				if (poll.done) {
					data = {...poll, community_index: start.community_index};
					(poll.errors ?? []).forEach(error => this.log(`${node.ip}: ${error}`, 'warning'));
					break;
				}
			}
		}
		finally {
			// Normally already removed by the final poll; harmless otherwise.
			await this.post('netmapper.neighbors', {ip: node.ip, proxyid, hostid: start.hostid, step: 'stop'})
				.catch(e => this.log(e.message, 'error'));
		}

		if (data === null) {
			throw new Error(this.abort ? 'Stopped.' : 'Timeout waiting for the proxy to collect SNMP data. '
				+ 'Check that the proxy is online, can reach the device and uses the right community.'
			);
		}

		return data;
	}

	applyNeighbors(node, data) {
		(data.log ?? []).forEach(line => this.log(`${node.ip}: ${line}`));

		for (const entry of data.arp ?? []) {
			this.arp.set(entry.mac, entry.ip);
		}

		this.addMacs(node, data.own_macs ?? []);
		node = this.nodes.get(node.id) ?? node;

		if (data.hostname && !node.sysname) {
			node.sysname = data.hostname;
		}

		// Learn how this switch identifies itself to its neighbors before resolving them.
		node = this.registerIdentity(node, data.local);
		node.explored = true;
		node.identified = true;
		node.network_device = true;
		node.port_roles = data.ports ?? [];
		node.info.neighbors = data.neighbors ?? [];

		if (data.classification) {
			this.applyClassification(node, data.classification);
		}

		const hosts = data.hosts ?? {};
		const fresh = [];

		for (const neighbor of data.neighbors ?? []) {
			const [target, created] = this.resolveNeighbor(neighbor, hosts);

			if (created) {
				fresh.push(target);
			}

			if (target.id !== node.id) {
				this.upsertLink(node.id, neighbor.local_port, target.id,
					neighbor.remote_port || neighbor.remote_port_desc, neighbor.protocol
				);
			}
		}

		for (const access of data.access ?? []) {
			const [target, created] = this.resolveMac(access.mac, access.ip, hosts);

			if (target.id === node.id) {
				continue;
			}

			if (created) {
				fresh.push(target);
			}

			this.upsertLink(node.id, access.port, target.id, '', 'mac');
		}

		this.normalizeLinks();
		this.placeAround(node, fresh.filter(item => this.nodes.has(item.id)));
		this.render();
		this.renderPanel();
		this.persist();

		this.log(`${node.ip}: ${(data.neighbors ?? []).length} LLDP/CDP neighbors, ${(data.access ?? []).length} access ports `
			+ `(single MAC), ${fresh.filter(item => this.nodes.has(item.id)).length} new devices on the map.`
		);
	}

	/**
	 * Finds the map node of an LLDP/CDP neighbor. Order: management IP, chassis ID (any subtype), MAC address,
	 * system name (compared with SNMP sysName, LLDP names and Zabbix host names). Creates a provisional node otherwise.
	 */
	resolveNeighbor(neighbor, hosts) {
		const chassis = view.constructor.chassisKey(neighbor.remote_chassis);
		const chassis_mac = view.constructor.isMac(chassis) ? chassis : null;
		let node = this.nodeByIp(neighbor.remote_ip);

		if (!node && chassis && this.chassis_index.has(chassis)) {
			node = this.nodes.get(this.chassis_index.get(chassis)) ?? null;
		}

		if (!node && chassis_mac && this.mac_index.has(chassis_mac)) {
			node = this.nodes.get(this.mac_index.get(chassis_mac)) ?? null;
		}

		if (!node && neighbor.remote_sysname) {
			const candidates = [...this.nodes.values()].filter(candidate =>
				this.nodeNames(candidate).some(name => view.constructor.sameName(name, neighbor.remote_sysname))
			);

			// Prefer an identified node over a provisional one.
			node = candidates.find(candidate => !view.constructor.isProvisional(candidate)) ?? candidates[0] ?? null;
		}

		let created = false;

		if (!node) {
			const id = neighbor.remote_ip
				? 'ip:' + neighbor.remote_ip
				: 'lldp:' + (chassis || neighbor.remote_sysname);

			const caps = (neighbor.remote_caps || '').toLowerCase();
			const type = /router/.test(caps) && !/bridge/.test(caps) ? 'router'
				: /bridge|switch/.test(caps) ? 'switch'
				: /wlan|trans/.test(caps) ? 'ap'
				: 'unknown';

			node = this.createNode(id, {
				ip: neighbor.remote_ip || null,
				sysname: neighbor.remote_sysname,
				type,
				network_device: type === 'switch' || type === 'router' || neighbor.protocol === 'cdp',
				info: {lldp: {sysdesc: neighbor.remote_sysdesc, chassis: neighbor.remote_chassis}}
			});
			created = true;
		}

		if (neighbor.remote_ip && !node.ip) {
			node.ip = neighbor.remote_ip;
			this.ip_alias.set(neighbor.remote_ip, node.id);
		}

		if (neighbor.remote_ip && hosts[neighbor.remote_ip]) {
			node.host = hosts[neighbor.remote_ip];
		}

		if (neighbor.remote_sysname) {
			node.sysname = node.sysname || neighbor.remote_sysname;

			if (!node.lldp_names.includes(neighbor.remote_sysname)) {
				node.lldp_names.push(neighbor.remote_sysname);
			}
		}

		if (chassis) {
			if (!node.chassis_ids.includes(chassis)) {
				node.chassis_ids.push(chassis);
			}

			this.chassis_index.set(chassis, node.id);
		}

		if (chassis_mac) {
			this.addMacs(node, [chassis_mac]);
		}

		// addMacs() may have merged the node into an already identified one.
		const resolved = this.nodes.get(node.id) ?? this.nodes.get(this.chassis_index.get(chassis)) ?? node;

		return [resolved, created && resolved === node];
	}

	resolveMac(mac, ip, hosts) {
		ip = ip || this.arp.get(mac) || '';

		if (this.mac_index.has(mac) && this.nodes.has(this.mac_index.get(mac))) {
			const node = this.nodes.get(this.mac_index.get(mac));

			if (ip && !node.ip) {
				node.ip = ip;
				this.ip_alias.set(ip, node.id);
			}

			return [node, false];
		}

		const existing = this.nodeByIp(ip);

		if (existing) {
			this.addMacs(existing, [mac]);

			return [this.nodes.get(existing.id) ?? existing, false];
		}

		const node = this.createNode(ip ? 'ip:' + ip : 'mac:' + mac, {ip: ip || null, label: ip || mac});

		if (ip && hosts[ip]) {
			node.host = hosts[ip];
		}

		this.addMacs(node, [mac]);

		return [node, true];
	}


	async exploreAll() {
		if (this.busy) {
			return;
		}

		this.setBusy(true);

		try {
			for (let round = 0; round < 50 && !this.abort; round++) {
				const pending = [...this.nodes.values()].filter(node => node.ip && node.network_device && !node.explored
					&& !node.explore_failed
				);

				if (!pending.length) {
					break;
				}

				for (const node of pending) {
					if (this.abort) {
						break;
					}

					await this.findNeighbors(node);

					if (!node.explored) {
						node.explore_failed = true;
					}
				}
			}

			this.log('Neighbor discovery of all switches finished.' + (this.abort ? ' (stopped)' : ''));
		}
		finally {
			this.setBusy(false);
			this.persist();
		}
	}

	// ---------------------------------------------------------------- layout

	placeGrid(nodes) {
		if (!nodes.length) {
			return;
		}

		const existing = [...this.nodes.values()].filter(node => !nodes.includes(node));
		const max_y = existing.length ? Math.max(...existing.map(node => node.y)) + 180 : 0;
		const columns = Math.max(6, Math.ceil(Math.sqrt(nodes.length * 2)));

		nodes.sort((a, b) => view.constructor.ipToInt(a.ip ?? '0.0.0.0') - view.constructor.ipToInt(b.ip ?? '0.0.0.0'));
		nodes.forEach((node, i) => {
			node.x = (i % columns) * 170;
			node.y = max_y + Math.floor(i / columns) * 150;
		});
	}

	placeAround(center, nodes) {
		const count = nodes.length;
		const radius = Math.max(200, count * 28);

		nodes.forEach((node, i) => {
			const angle = (2 * Math.PI * i) / Math.max(count, 1) + Math.PI / 2;

			node.x = center.x + radius * Math.cos(angle);
			node.y = center.y + radius * Math.sin(angle);
		});
	}

	autoLayout() {
		const nodes = [...this.nodes.values()];
		const links = [...this.links.values()];

		if (nodes.length < 2) {
			return;
		}

		const by_id = new Map(nodes.map(node => [node.id, node]));
		const k_repulse = 60000;
		const rest = 190;

		for (let iteration = 0; iteration < 300; iteration++) {
			const temperature = 30 * (1 - iteration / 300) + 1;
			const force = new Map(nodes.map(node => [node.id, {x: 0, y: 0}]));

			for (let i = 0; i < nodes.length; i++) {
				for (let j = i + 1; j < nodes.length; j++) {
					const a = nodes[i], b = nodes[j];
					let dx = a.x - b.x, dy = a.y - b.y;
					let d2 = dx * dx + dy * dy;

					if (d2 < 1) {
						dx = Math.random() - 0.5;
						dy = Math.random() - 0.5;
						d2 = 1;
					}

					if (d2 > 1000000) {
						continue;
					}

					const f = k_repulse / d2;
					const d = Math.sqrt(d2);

					force.get(a.id).x += f * dx / d;
					force.get(a.id).y += f * dy / d;
					force.get(b.id).x -= f * dx / d;
					force.get(b.id).y -= f * dy / d;
				}
			}

			for (const link of links) {
				const a = by_id.get(link.a), b = by_id.get(link.b);

				if (!a || !b) {
					continue;
				}

				const dx = b.x - a.x, dy = b.y - a.y;
				const d = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
				const f = (d - rest) * 0.08;

				force.get(a.id).x += f * dx / d;
				force.get(a.id).y += f * dy / d;
				force.get(b.id).x -= f * dx / d;
				force.get(b.id).y -= f * dy / d;
			}

			for (const node of nodes) {
				if (node.fixed) {
					continue;
				}

				const f = force.get(node.id);
				const length = Math.sqrt(f.x * f.x + f.y * f.y);

				if (length > 0) {
					node.x += f.x / length * Math.min(length, temperature);
					node.y += f.y / length * Math.min(length, temperature);
				}
			}
		}
	}

	// ---------------------------------------------------------------- SVG rendering

	buildSvg() {
		const icons = {
			switch: '<rect x="2" y="8" width="20" height="8" rx="1.5"/><path d="M5.5 12h1.5M9 12h1.5M12.5 12h1.5M16 12h2.5"/>',
			router: '<circle cx="12" cy="12" r="8.5"/><path d="M7 12h10M12 7v10M15 9.5l2 2.5-2 2.5M9 9.5L7 12l2 2.5"/>',
			firewall: '<rect x="3" y="5" width="18" height="14"/><path d="M3 9.7h18M3 14.3h18M9 5v4.7M15 9.7v4.6M9 14.3V19"/>',
			server: '<rect x="6" y="2.5" width="12" height="19" rx="1.5"/><path d="M9 6.5h6M9 10h6M11.5 17.5h1"/>',
			plc: '<rect x="4" y="6" width="16" height="12" rx="1"/><path d="M7 6V3.5M10.3 6V3.5M13.6 6V3.5M17 6V3.5M7 18v2.5M10.3 18v2.5M13.6 18v2.5M17 18v2.5M8 12h8"/>',
			hmi: '<rect x="2.5" y="4" width="19" height="13" rx="1.5"/><path d="M9 20.5h6M12 17v3.5M6 8h7M6 11h4"/>',
			ap: '<path d="M4.5 9.5a11 11 0 0 1 15 0M7.5 12.5a6.5 6.5 0 0 1 9 0"/><circle cx="12" cy="16" r="1.6"/>',
			camera: '<rect x="2.5" y="7.5" width="13" height="9" rx="1.5"/><path d="M15.5 11l6-3.5v9l-6-3.5z"/>',
			printer: '<rect x="6" y="3" width="12" height="6"/><rect x="2.5" y="9" width="19" height="8" rx="1"/><rect x="6.5" y="14" width="11" height="7"/>',
			gateway: '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 10h8M13 7l3 3-3 3M16 14H8M11 17l-3-3 3-3"/>',
			io: '<rect x="5" y="3" width="14" height="18" rx="1"/><path d="M8 7h2M8 11h2M8 15h2M14 7h2M14 11h2M14 15h2"/>',
			drive: '<rect x="5" y="3" width="14" height="18" rx="1"/><circle cx="12" cy="10" r="3.5"/><path d="M9 17h6"/>',
			ups: '<rect x="6" y="3" width="12" height="18" rx="1.5"/><path d="M12.8 7l-3 5h4l-3 5"/>',
			unknown: '<circle cx="12" cy="12" r="8.5"/><path d="M9.7 9.5a2.4 2.4 0 1 1 3.2 2.3c-.6.3-.9.8-.9 1.4v.8M12 16.8v.4"/>'
		};

		const symbols = Object.entries(icons).map(([name, body]) =>
			`<symbol id="nm-icon-${name}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"`
				+ ` stroke-linecap="round" stroke-linejoin="round">${body}</symbol>`
		).join('');

		const canvas = document.getElementById('nm-canvas');
		const svg = this.el('svg', {class: 'nm-svg', xmlns: 'http://www.w3.org/2000/svg'});

		svg.innerHTML = `<defs>${symbols}</defs>`;
		this.g_links = this.el('g', {class: 'nm-links'});
		this.g_nodes = this.el('g', {class: 'nm-nodes'});
		svg.append(this.g_links, this.g_nodes);
		canvas.append(svg);
		this.svg = svg;

		this.bindCanvas();
	}

	applyViewBox() {
		const {x, y, w, h} = this.view_box;

		this.svg.setAttribute('viewBox', `${x} ${y} ${w} ${h}`);
	}

	clientToSvg(event) {
		const rect = this.svg.getBoundingClientRect();
		const scale = Math.max(this.view_box.w / rect.width, this.view_box.h / rect.height);
		const offset_x = (rect.width * scale - this.view_box.w) / 2;
		const offset_y = (rect.height * scale - this.view_box.h) / 2;

		return {
			x: this.view_box.x - offset_x + (event.clientX - rect.left) * scale,
			y: this.view_box.y - offset_y + (event.clientY - rect.top) * scale,
			scale
		};
	}

	bindCanvas() {
		let drag = null;

		this.svg.addEventListener('pointerdown', event => {
			const node_element = event.target.closest('.nm-node');

			if (event.target.closest('.nm-badge')) {
				return;
			}

			const point = this.clientToSvg(event);

			if (node_element) {
				const node = this.nodes.get(node_element.dataset.id);

				drag = {type: 'node', node, dx: point.x - node.x, dy: point.y - node.y, moved: false};
				this.select(node.id);
			}
			else {
				drag = {type: 'pan', start_x: event.clientX, start_y: event.clientY, box: {...this.view_box},
					scale: point.scale, moved: false
				};
			}

			this.svg.setPointerCapture(event.pointerId);
		});

		this.svg.addEventListener('pointermove', event => {
			if (!drag) {
				return;
			}

			if (drag.type === 'node') {
				const point = this.clientToSvg(event);

				drag.node.x = point.x - drag.dx;
				drag.node.y = point.y - drag.dy;
				drag.node.fixed = true;
				drag.moved = true;
				this.render();
			}
			else {
				this.view_box.x = drag.box.x - (event.clientX - drag.start_x) * drag.scale;
				this.view_box.y = drag.box.y - (event.clientY - drag.start_y) * drag.scale;
				drag.moved = true;
				this.applyViewBox();
			}
		});

		this.svg.addEventListener('pointerup', () => {
			if (drag && drag.type === 'pan' && !drag.moved) {
				this.select(null);
			}

			if (drag && drag.type === 'node' && drag.moved) {
				this.persist();
			}

			drag = null;
		});

		this.svg.addEventListener('wheel', event => {
			event.preventDefault();

			const point = this.clientToSvg(event);
			const factor = event.deltaY > 0 ? 1.15 : 1 / 1.15;
			const w = Math.min(Math.max(this.view_box.w * factor, 200), 50000);
			const ratio = w / this.view_box.w;

			this.view_box = {
				x: point.x - (point.x - this.view_box.x) * ratio,
				y: point.y - (point.y - this.view_box.y) * ratio,
				w,
				h: this.view_box.h * ratio
			};
			this.applyViewBox();
		}, {passive: false});
	}

	fit() {
		const nodes = [...this.nodes.values()];

		if (!nodes.length) {
			this.view_box = {x: -100, y: -100, w: 1600, h: 900};
		}
		else {
			const xs = nodes.map(node => node.x), ys = nodes.map(node => node.y);
			const min_x = Math.min(...xs) - 120, max_x = Math.max(...xs) + 120;
			const min_y = Math.min(...ys) - 100, max_y = Math.max(...ys) + 140;

			this.view_box = {x: min_x, y: min_y, w: Math.max(max_x - min_x, 400), h: Math.max(max_y - min_y, 300)};
		}

		this.applyViewBox();
	}

	select(id) {
		this.selected = id;
		this.render();
		this.renderPanel();
	}

	render() {
		this.g_links.replaceChildren();
		this.g_nodes.replaceChildren();

		for (const link of this.links.values()) {
			const a = this.nodes.get(link.a), b = this.nodes.get(link.b);

			if (!a || !b) {
				continue;
			}

			const g = this.el('g', {class: `nm-link nm-link-${link.protocol}`});
			const label_at = (from, to, ratio) => ({x: from.x + (to.x - from.x) * ratio, y: from.y + (to.y - from.y) * ratio});

			g.append(
				this.el('title', {text: `${this.nodeLabel(a)} ${link.a_port || '?'} ⇄ ${link.b_port || '?'} ${this.nodeLabel(b)}`
					+ ` (${link.protocol.toUpperCase()})`
				}),
				this.el('line', {x1: a.x, y1: a.y, x2: b.x, y2: b.y})
			);

			for (const [port, from, to] of [[link.a_port, a, b], [link.b_port, b, a]]) {
				if (port) {
					const p = label_at(from, to, 0.28);

					g.append(this.el('text', {x: p.x, y: p.y, class: 'nm-port', 'text-anchor': 'middle', text: port}));
				}
			}

			this.g_links.append(g);
		}

		for (const node of this.nodes.values()) {
			const classes = ['nm-node', `nm-type-${node.type}`];

			if (node.host) {
				classes.push('nm-monitored');
			}

			if (node.id === this.selected) {
				classes.push('nm-selected');
			}

			if (!node.ip) {
				classes.push('nm-provisional');
			}

			const g = this.el('g', {class: classes.join(' '), transform: `translate(${node.x},${node.y})`, 'data-id': node.id});
			const icon = document.getElementById('nm-icon-' + node.type) ? node.type : 'unknown';

			g.append(
				this.el('title', {text: [this.nodeLabel(node), node.ip, node.vendor_name, node.model].filter(Boolean).join('\n')}),
				this.el('circle', {r: 24, class: 'nm-node-bg'}),
				this.el('use', {href: '#nm-icon-' + icon, x: -15, y: -15, width: 30, height: 30, class: 'nm-icon'}),
				this.el('text', {y: 40, 'text-anchor': 'middle', class: 'nm-label', text: this.nodeLabel(node).substring(0, 32)}),
				this.el('text', {y: 54, 'text-anchor': 'middle', class: 'nm-sublabel',
					text: (node.ip && this.nodeLabel(node) !== node.ip) ? node.ip : (node.vendor_name || '')
				})
			);

			if (!node.host && node.ip) {
				const badge = this.el('g', {class: 'nm-badge', transform: 'translate(18,-18)',
					onclick: event => {
						event.stopPropagation();
						this.openAddHost(node);
					}
				}, [
					this.el('title', {text: this.t('add_host')}),
					this.el('circle', {r: 8}),
					this.el('path', {d: 'M-4 0h8M0 -4v8'})
				]);

				g.append(badge);
			}

			if (node.network_device && !node.explored) {
				g.append(this.el('circle', {r: 4, cx: -19, cy: -19, class: 'nm-dot-pending'},
					[this.el('title', {text: this.t('find_neighbors')})]
				));
			}

			this.g_nodes.append(g);
		}
	}

	// ---------------------------------------------------------------- side panel

	renderPanel() {
		const panel = document.getElementById('nm-panel');
		const node = this.selected ? this.nodes.get(this.selected) : null;

		panel.replaceChildren();

		if (!node) {
			const counts = {};

			for (const n of this.nodes.values()) {
				counts[n.type] = (counts[n.type] ?? 0) + 1;
			}

			panel.append(
				this.el('h4', {text: 'Network mapper'}),
				this.el('div', {class: 'nm-hint'}, `${this.nodes.size} devices, ${this.links.size} connections.`),
				this.el('ul', {class: 'nm-kv'}, Object.entries(counts).map(([type, count]) =>
					this.el('li', {}, [this.el('span', {text: type}), this.el('b', {text: String(count)})])
				)),
				this.el('div', {class: 'nm-legend'}, [
					this.el('div', {}, [this.el('i', {class: 'nm-legend-lldp'}), ' LLDP / CDP']),
					this.el('div', {}, [this.el('i', {class: 'nm-legend-mac'}), ' MAC table (single MAC port)']),
					this.el('div', {}, [this.el('i', {class: 'nm-legend-monitored'}), ' ' + this.t('in_zabbix')]),
					this.el('div', {}, [this.el('i', {class: 'nm-legend-new'}), ' ' + this.t('not_in_zabbix')])
				])
			);

			return;
		}

		const button = (label, handler, alt = true) => this.el('button', {type: 'button', class: alt ? 'btn-alt' : '',
			onclick: handler
		}, label);

		const actions = this.el('div', {class: 'nm-panel-actions'});

		if (node.ip) {
			actions.append(button(this.t('identify'), () => this.identify(node)));
		}

		if (node.ip && (node.network_device || node.snmp)) {
			actions.append(button(this.t('find_neighbors'), () => this.findNeighbors(node), false));
		}

		if (node.ip) {
			actions.append(button(this.t('cli_paste'), () => this.openCliPaste(node)));
		}

		if (!node.host && node.ip) {
			actions.append(button(this.t('add_host'), () => this.openAddHost(node)));
		}

		actions.append(
			button(node.fixed ? this.t('unpin') : this.t('pin'), () => {
				node.fixed = !node.fixed;
				this.renderPanel();
				this.persist();
			}),
			button(this.t('remove'), () => this.removeNode(node.id))
		);

		const rows = [
			['IP', node.ip],
			['MAC', node.macs.slice(0, 3).join(', ') + (node.macs.length > 3 ? ` (+${node.macs.length - 3})` : '')],
			['Type', node.type],
			['Vendor', node.vendor_name],
			['Model', node.model],
			['sysName', node.sysname],
			['sysDescr', node.snmp?.system?.sysdescr],
			['Location', node.snmp?.system?.syslocation],
			['SNMP', node.snmp ? `v${node.snmp.version === 2 ? '2c' : node.snmp.version}` : ''],
			['Open TCP', (node.ports ?? []).join(', ')],
			['HTTP', node.info.http ? `${node.info.http.status} ${node.info.http.title} ${node.info.http.server}` : ''],
			['HTTPS', node.info.https ? `${node.info.https.status} ${node.info.https.title} ${node.info.https.certificate}` : ''],
			['SSH', node.info.ssh?.banner],
			['Telnet', node.info.telnet?.banner ? node.info.telnet.banner.substring(0, 160) : ''],
			['EtherNet/IP', node.info.enip ? `${node.info.enip.product_name} (${node.info.enip.device_type_name}, `
				+ `rev ${node.info.enip.revision}, SN ${node.info.enip.serial})` : ''
			],
			['LLDP', node.info.lldp?.sysdesc],
			['LLDP names', node.lldp_names.filter(name => name !== node.sysname).join(', ')],
			['Chassis ID', node.chassis_ids.join(', ')],
			['Other IPs', node.extra_ips.join(', ')]
		].filter(([, value]) => value);

		const host_block = node.host
			? this.el('div', {class: 'nm-host'}, [
				this.el('b', {text: this.t('in_zabbix') + ': '}),
				node.host.name, ' ',
				this.el('a', {href: `zabbix.php?action=problem.view&filter_set=1&hostids%5B%5D=${node.host.hostid}`,
					target: '_blank', text: this.t('problems')
				}), ' · ',
				this.el('a', {href: `zabbix.php?action=latest.view&filter_set=1&hostids%5B%5D=${node.host.hostid}`,
					target: '_blank', text: this.t('latest_data')
				}), ' · ',
				this.el('a', {href: `zabbix.php?action=host.edit&hostid=${node.host.hostid}`, target: '_blank',
					text: this.t('configuration')
				})
			])
			: this.el('div', {class: 'nm-host nm-host-new', text: this.t('not_in_zabbix')});

		panel.append(
			this.el('h4', {text: this.nodeLabel(node)}),
			host_block,
			actions,
			this.el('table', {class: 'nm-props'}, rows.map(([key, value]) =>
				this.el('tr', {}, [this.el('th', {text: key}), this.el('td', {text: String(value)})])
			))
		);

		const others = [...this.nodes.values()].filter(other => other !== node)
			.sort((a, b) => this.nodeLabel(a).localeCompare(this.nodeLabel(b)));

		if (others.length) {
			const merge_select = this.el('select', {class: 'nm-merge-select'}, [
				this.el('option', {value: '', text: 'Same device as…'}),
				...others.map(other => this.el('option', {value: other.id,
					text: this.nodeLabel(other) + (other.ip && other.ip !== this.nodeLabel(other) ? ` (${other.ip})` : '')
				}))
			]);

			panel.append(this.el('div', {class: 'nm-merge'}, [
				merge_select,
				button('Merge with', () => merge_select.value && this.mergeManually(node, merge_select.value))
			]));
		}

		const links = [...this.links.values()].filter(link => link.a === node.id || link.b === node.id);

		if (links.length) {
			panel.append(this.el('h5', {text: this.t('neighbors')}), this.el('table', {class: 'nm-props'}, links.map(link => {
				const local = link.a === node.id ? link.a_port : link.b_port;
				const remote = link.a === node.id ? link.b_port : link.a_port;
				const other = this.nodes.get(link.a === node.id ? link.b : link.a);

				return this.el('tr', {class: 'nm-clickable', onclick: () => this.select(other.id)}, [
					this.el('th', {text: local || '?'}),
					this.el('td', {text: `${this.nodeLabel(other)} ${remote ? '(' + remote + ')' : ''} · ${link.protocol.toUpperCase()}`})
				]);
			})));
		}

		if (node.port_roles?.length) {
			panel.append(this.el('h5', {text: this.t('ports')}), this.el('table', {class: 'nm-props nm-ports'},
				node.port_roles.map(port => this.el('tr', {}, [
					this.el('th', {text: port.port}),
					this.el('td', {class: 'nm-role-' + port.role, text: `${port.role} · ${port.mac_count} MAC`})
				]))
			));
		}
	}

	// ---------------------------------------------------------------- modals

	openModal(title, body, buttons) {
		const backdrop = document.getElementById('nm-modal');
		const close = () => {
			backdrop.hidden = true;
			backdrop.replaceChildren();
		};

		const footer = this.el('div', {class: 'nm-modal-footer'}, buttons.map(([label, handler, primary]) =>
			this.el('button', {type: 'button', class: primary ? '' : 'btn-alt', onclick: () => handler(close)}, label)
		));

		backdrop.replaceChildren(this.el('div', {class: 'nm-modal', role: 'dialog', 'aria-modal': 'true'}, [
			this.el('div', {class: 'nm-modal-header'}, [
				this.el('h4', {text: title}),
				this.el('button', {type: 'button', class: 'btn-overlay-close', title: this.t('close'), onclick: close})
			]),
			this.el('div', {class: 'nm-modal-body'}, body),
			footer
		]));
		backdrop.hidden = false;

		return close;
	}

	confirmClear() {
		this.openModal(this.t('clear'), [this.el('p', {text: this.t('confirm_clear')})], [
			[this.t('clear'), close => {
				this.nodes.clear();
				this.links.clear();
				this.mac_index.clear();
				this.chassis_index.clear();
				this.ip_alias.clear();
				this.arp.clear();
				this.selected = null;
				this.render();
				this.renderPanel();
				this.persist();
				this.fit();
				close();
			}, true],
			[this.t('cancel'), close => close()]
		]);
	}

	openCliPaste(node) {
		const profiles = this.config.vendor_profiles;
		const current = profiles[node.vendor] ? node.vendor
			: ({hp: 'aruba', belden: 'hirschmann'}[node.vendor] ?? 'generic');

		const vendor_select = this.el('select', {id: 'nm-cli-vendor'}, Object.entries(profiles).map(([key, profile]) =>
			this.el('option', {value: key, selected: key === current, text: profile.name})
		));

		const commands = this.el('div', {class: 'nm-commands'});
		const sections = [
			['paging', 'Session (optional, disables paging)'], ['version', 'Version'], ['lldp', 'LLDP neighbors'],
			['cdp', 'CDP neighbors'], ['mac', 'MAC address table'], ['arp', 'ARP table']
		];

		const renderCommands = () => {
			const profile = profiles[vendor_select.value];

			commands.replaceChildren(this.el('div', {class: 'nm-hint', text: 'Mode: ' + profile.mode}));

			for (const [section, label] of sections) {
				if (!profile[section]?.length) {
					continue;
				}

				commands.append(this.el('div', {class: 'nm-command-row'}, [
					this.el('span', {class: 'nm-command-label', text: label}),
					...profile[section].map(command => this.el('code', {
						title: this.t('copy'),
						onclick: event => {
							navigator.clipboard?.writeText(command).then(() => {
								event.target.classList.add('nm-copied');
								setTimeout(() => event.target.classList.remove('nm-copied'), 900);
							});
						}
					}, command))
				]));
			}
		};

		vendor_select.addEventListener('change', renderCommands);
		renderCommands();

		const area = (name, label) => this.el('div', {class: 'nm-paste'}, [
			this.el('label', {for: 'nm-paste-' + name, text: label}),
			this.el('textarea', {id: 'nm-paste-' + name, rows: 5, spellcheck: 'false', autocomplete: 'off'})
		]);

		this.openModal(`${this.t('cli_paste')}: ${this.nodeLabel(node)} (${node.ip})`, [
			this.el('p', {class: 'nm-hint', text: this.t('cli_note')}),
			this.el('div', {class: 'nm-field'}, [this.el('label', {text: 'Vendor / CLI'}), vendor_select]),
			commands,
			area('version', 'Version output'),
			area('lldp', 'LLDP output'),
			area('cdp', 'CDP output'),
			area('mac', 'MAC address table output'),
			area('arp', 'ARP table output')
		], [
			[this.t('parse'), async close => {
				const text = name => document.getElementById('nm-paste-' + name).value;

				try {
					const data = await this.post('netmapper.cli.parse', {
						ip: node.ip,
						vendor: vendor_select.value,
						text_version: text('version'),
						text_lldp: text('lldp'),
						text_cdp: text('cdp'),
						text_mac: text('mac'),
						text_arp: text('arp'),
						own_macs: node.macs
					});

					close();
					this.applyNeighbors(node, data);
				}
				catch (e) {
					this.log(`${node.ip}: ${e.message}`, 'error');
				}
			}, true],
			[this.t('cancel'), close => close()]
		]);
	}

	suggestTemplates(node) {
		const by_name = new Map(this.config.templates.map(template => [template.name, template.templateid]));
		const wanted = [];

		if (node.snmp) {
			if (node.vendor === 'cisco' || node.vendor === 'rockwell' && /stratix|ios/i.test(node.snmp.system?.sysdescr ?? '')) {
				wanted.push('Cisco IOS by SNMP');
			}
			else if (node.vendor === 'hirschmann') {
				wanted.push('Network Generic Device by SNMP');
			}
			else if (node.type === 'server' && node.vendor === 'linux') {
				wanted.push('Linux by SNMP');
			}
			else if (node.type === 'server' && node.vendor === 'microsoft') {
				wanted.push('Windows by SNMP');
			}
			else {
				wanted.push('Network Generic Device by SNMP');
			}
		}
		else {
			wanted.push('ICMP Ping');
		}

		return wanted.map(name => by_name.get(name)).filter(Boolean);
	}

	openAddHost(node) {
		const host_name = (node.sysname || node.ip || '').replace(/[^0-9a-zA-Z_. \-]/g, '_').substring(0, 128);
		const visible = node.sysname && node.sysname !== host_name ? node.sysname : '';
		const suggested = this.suggestTemplates(node);

		const group_select = this.el('select', {id: 'nm-host-groups', multiple: true, size: 6},
			this.config.groups.map(group => this.el('option', {value: group.groupid, text: group.name}))
		);

		const template_select = this.el('select', {id: 'nm-host-templates', multiple: true, size: 8},
			this.config.templates.map(template => this.el('option', {value: template.templateid, text: template.name,
				selected: suggested.includes(template.templateid)
			}))
		);

		const template_filter = this.el('input', {type: 'text', placeholder: this.t('filter'), autocomplete: 'off',
			oninput: event => {
				const filter = event.target.value.toLowerCase();

				for (const option of template_select.options) {
					option.hidden = filter !== '' && !option.text.toLowerCase().includes(filter) && !option.selected;
				}
			}
		});

		const has_snmp = Boolean(node.snmp);
		const description = [
			'Added by Network mapper.',
			node.vendor_name && `Vendor: ${node.vendor_name}`,
			node.model && `Model: ${node.model}`,
			node.macs[0] && `MAC: ${node.macs[0]}`
		].filter(Boolean).join('\n');

		const input = (id, value, attrs = {}) => this.el('input', {id, type: 'text', value, autocomplete: 'off', ...attrs});
		const field = (label, control) => this.el('div', {class: 'nm-form-row'}, [this.el('label', {text: label}), control]);

		this.openModal(`${this.t('add_host')}: ${node.ip}`, [
			field(this.t('host_name'), input('nm-host-name', host_name, {maxlength: 128})),
			field(this.t('visible_name'), input('nm-host-visible', visible, {maxlength: 128})),
			field(this.t('host_groups'), group_select),
			field(this.t('templates'), this.el('div', {}, [template_filter, template_select])),
			field(this.t('interfaces'), this.el('div', {class: 'nm-checks'}, [
				this.el('label', {}, [this.el('input', {type: 'checkbox', id: 'nm-host-agent'}), ' Zabbix agent']),
				this.el('label', {}, [this.el('input', {type: 'checkbox', id: 'nm-host-snmp', checked: has_snmp}),
					' SNMP'
				]),
				this.el('select', {id: 'nm-host-snmp-version'}, [
					this.el('option', {value: '2', text: 'v2c', selected: (node.snmp?.version ?? 2) == 2}),
					this.el('option', {value: '1', text: 'v1', selected: node.snmp?.version == 1}),
					this.el('option', {value: '3', text: 'v3 ({$SNMPV3_*} macros)', selected: node.snmp?.version == 3})
				]),
				input('nm-host-community', '{$SNMP_COMMUNITY}', {title: 'SNMP community (macro recommended)'})
			])),
			field(this.t('description'), this.el('textarea', {id: 'nm-host-description', rows: 3, text: description}))
		], [
			[this.t('add_host'), async close => {
				const selected = select => [...select.selectedOptions].map(option => option.value);

				try {
					const data = await this.post('netmapper.host.create', {
						host: document.getElementById('nm-host-name').value.trim(),
						name: document.getElementById('nm-host-visible').value.trim(),
						ip: node.ip,
						groupids: selected(group_select),
						templateids: selected(template_select),
						iface_agent: document.getElementById('nm-host-agent').checked ? 1 : 0,
						iface_snmp: document.getElementById('nm-host-snmp').checked ? 1 : 0,
						snmp_version: document.getElementById('nm-host-snmp-version').value,
						snmp_community: document.getElementById('nm-host-community').value,
						description: document.getElementById('nm-host-description').value
					});

					node.host = data.host;
					close();
					this.log(`${node.ip}: host "${data.host.name}" created in Zabbix.`);
					this.render();
					this.renderPanel();
					this.persist();
				}
				catch (e) {
					this.log(`${node.ip}: ${e.message}`, 'error');
				}
			}, true],
			[this.t('cancel'), close => close()]
		]);
	}

	saveZabbixMap() {
		const name_input = this.el('input', {type: 'text', id: 'nm-map-name', autocomplete: 'off',
			value: 'Network mapper ' + new Date().toISOString().substring(0, 16).replace('T', ' ')
		});

		this.openModal('Save as Zabbix map', [
			this.el('div', {class: 'nm-form-row'}, [this.el('label', {text: this.t('map_name')}), name_input])
		], [
			[this.t('save'), async close => {
				try {
					const data = await this.post('netmapper.map.save', {
						name: name_input.value.trim(),
						map: JSON.stringify(this.serialize())
					});

					close();
					this.log(`${this.t('map_saved')}: zabbix.php?action=map.view&sysmapid=${data.sysmapid}`);
					window.open('zabbix.php?action=map.view&sysmapid=' + encodeURIComponent(data.sysmapid), '_blank');
				}
				catch (e) {
					this.log(e.message, 'error');
				}
			}, true],
			[this.t('cancel'), close => close()]
		]);
	}

	// ---------------------------------------------------------------- persistence (map only, never credentials)

	serialize() {
		return {
			format: 'netmapper/1',
			nodes: [...this.nodes.values()].map(node => ({
				id: node.id, ip: node.ip, label: this.nodeLabel(node), sysname: node.sysname, type: node.type,
				vendor: node.vendor, vendor_name: node.vendor_name, model: node.model, macs: node.macs.slice(0, 64),
				ports: node.ports, hostid: node.host?.hostid ?? null, host: node.host,
				snmp: node.snmp ? {version: node.snmp.version, community_index: node.snmp.community_index,
					system: node.snmp.system
				} : null,
				chassis_ids: node.chassis_ids, lldp_names: node.lldp_names, port_aliases: node.port_aliases,
				extra_ips: node.extra_ips, alive: Boolean(node.alive), identified: Boolean(node.identified),
				network_device: node.network_device, explored: node.explored, x: Math.round(node.x),
				y: Math.round(node.y), fixed: node.fixed, port_roles: node.port_roles, info: node.info
			})),
			links: [...this.links.values()].map(({a, b, a_port, b_port, protocol}) => ({a, b, a_port, b_port, protocol})),
			arp: [...this.arp.entries()]
		};
	}

	load(data) {
		if (!data || data.format !== 'netmapper/1' || !Array.isArray(data.nodes) || !Array.isArray(data.links)) {
			throw new Error('Invalid map file.');
		}

		this.nodes.clear();
		this.links.clear();
		this.mac_index.clear();
		this.chassis_index.clear();
		this.ip_alias.clear();
		this.arp = new Map(Array.isArray(data.arp) ? data.arp : []);

		for (const item of data.nodes) {
			if (typeof item.id !== 'string') {
				continue;
			}

			const node = this.createNode(item.id, {
				ip: item.ip ?? null, sysname: item.sysname ?? '', type: item.type ?? 'unknown', vendor: item.vendor ?? null,
				vendor_name: item.vendor_name ?? '', model: item.model ?? '', ports: item.ports ?? [], host: item.host ?? null,
				snmp: item.snmp ?? null, network_device: Boolean(item.network_device), explored: Boolean(item.explored),
				x: Number(item.x) || 0, y: Number(item.y) || 0, fixed: Boolean(item.fixed),
				port_roles: item.port_roles ?? [], info: item.info ?? {}, label: item.label ?? '',
				chassis_ids: Array.isArray(item.chassis_ids) ? item.chassis_ids : [],
				lldp_names: Array.isArray(item.lldp_names) ? item.lldp_names : [],
				port_aliases: item.port_aliases && typeof item.port_aliases === 'object' ? item.port_aliases : {},
				extra_ips: Array.isArray(item.extra_ips) ? item.extra_ips : [],
				alive: Boolean(item.alive), identified: Boolean(item.identified)
			});

			for (const ip of node.extra_ips) {
				this.ip_alias.set(ip, node.id);
			}

			for (const mac of item.macs ?? []) {
				node.macs.push(mac);
				this.mac_index.set(mac, node.id);
			}
		}

		for (const link of data.links) {
			if (this.nodes.has(link.a) && this.nodes.has(link.b)) {
				this.upsertLink(link.a, link.a_port, link.b, link.b_port, link.protocol);
			}
		}

		// Maps saved by older versions may contain duplicated devices.
		for (const node of [...this.nodes.values()]) {
			this.absorbDuplicates(node);
		}

		this.normalizeLinks();
	}

	storageKey() {
		return 'netmapper.map.' + this.config.userid;
	}

	persist() {
		try {
			localStorage.setItem(this.storageKey(), JSON.stringify(this.serialize()));
		}
		catch (e) {
			// Storage full or disabled: the map simply is not kept between page loads.
		}
	}

	restore() {
		try {
			const saved = localStorage.getItem(this.storageKey());

			if (saved) {
				this.load(JSON.parse(saved));
				this.log(`Map restored from this browser: ${this.nodes.size} devices, ${this.links.size} connections.`);
			}
		}
		catch (e) {
			this.log('Saved map could not be restored: ' + e.message, 'warning');
		}

		this.renderPanel();
	}

	exportJson() {
		const blob = new Blob([JSON.stringify(this.serialize(), null, 2)], {type: 'application/json'});
		const url = URL.createObjectURL(blob);
		const link = this.el('a', {href: url, download: `netmapper-${new Date().toISOString().substring(0, 10)}.json`});

		document.body.append(link);
		link.click();
		link.remove();
		setTimeout(() => URL.revokeObjectURL(url), 1000);
	}

	importJson() {
		const input = this.el('input', {type: 'file', accept: 'application/json,.json'});

		input.addEventListener('change', async () => {
			const file = input.files[0];

			if (!file) {
				return;
			}

			try {
				this.load(JSON.parse(await file.text()));
				this.selected = null;
				this.render();
				this.renderPanel();
				this.fit();
				this.persist();
				this.log(`Imported ${this.nodes.size} devices, ${this.links.size} connections.`);
			}
			catch (e) {
				this.log(e.message, 'error');
			}
		});

		input.click();
	}
};
</script>
