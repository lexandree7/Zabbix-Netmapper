<?php declare(strict_types = 0);
/**
 * @var CView $this
 * @var array $data
 */

$this->includeJsFile('netmapper.view.js.php');

// Source: frontend server or one of the proxies.
$source = (new CSelect('source'))
	->setId('nm-source')
	->setFocusableElementId('nm-source-focus')
	->addOption(new CSelectOption('server', _('Zabbix frontend server')));

foreach ($data['proxies'] as $proxyid => $name) {
	$source->addOption(new CSelectOption((string) $proxyid, _('Proxy').': '.$name));
}

$proxy_method = (new CSelect('proxy_method'))
	->setId('nm-proxy-method')
	->addOptions(CSelect::createOptionsFromArray([
		'script' => _('Remote command (fping on proxy)'),
		'drule' => _('Temporary discovery rule')
	]))
	->setValue('script');

$port_profile = (new CSelect('port_profile'))
	->setId('nm-port-profile')
	->addOptions(CSelect::createOptionsFromArray([
		'standard' => _('Standard IT/OT ports'),
		'minimal' => _('Minimal (22, 23, 80, 443)')
	]))
	->setValue('standard');

$snmp_version = (new CSelect('snmp_version'))
	->setId('nm-snmp-version')
	->addOptions(CSelect::createOptionsFromArray(['2' => 'v2c', '1' => 'v1', '3' => 'v3']))
	->setValue('2');

$v3_level = (new CSelect('v3_level'))
	->setId('nm-v3-level')
	->addOptions(CSelect::createOptionsFromArray(['2' => 'authPriv', '1' => 'authNoPriv', '0' => 'noAuthNoPriv']))
	->setValue('2');

$v3_auth = (new CSelect('v3_auth_proto'))
	->setId('nm-v3-auth-proto')
	->addOptions(CSelect::createOptionsFromArray(array_combine(
		['SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'MD5'], ['SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'MD5']
	)))
	->setValue('SHA');

$v3_priv = (new CSelect('v3_priv_proto'))
	->setId('nm-v3-priv-proto')
	->addOptions(CSelect::createOptionsFromArray(['AES' => 'AES128', 'AES192' => 'AES192', 'AES256' => 'AES256',
		'DES' => 'DES'
	]))
	->setValue('AES');

$field = static function (string $label, $control, string $class = ''): CDiv {
	return (new CDiv([new CTag('label', true, $label), $control]))->addClass('nm-field '.$class);
};

$toolbar = (new CDiv([
	(new CDiv([
		$field(_('Prefix / range'),
			(new CTextBox('targets'))
				->setId('nm-targets')
				->setAttribute('placeholder', '10.0.0.0/24, 10.0.1.10-50, 192.168.1.7')
				->setAttribute('autocomplete', 'off'),
			'nm-field-wide'
		),
		$field(_('Source'), $source),
		$field(_('Proxy method'), $proxy_method, 'nm-proxy-only'),
		(new CDiv([
			(new CSimpleButton(_('Scan')))->setId('nm-scan'),
			(new CSimpleButton(_('Stop')))->setId('nm-stop')->addClass(ZBX_STYLE_BTN_ALT)->setEnabled(false)
		]))->addClass('nm-buttons')
	]))->addClass('nm-row'),

	(new CDiv([
		(new CDiv([
			new CTag('label', true, _('Probes')),
			(new CCheckBox('probe_icmp'))->setId('nm-probe-icmp')->setChecked(true)
				->setLabel($data['fping'] ? 'ICMP (fping)' : 'ICMP (fping n/a)'),
			(new CCheckBox('probe_tcp'))->setId('nm-probe-tcp')->setChecked(true)->setLabel('TCP'),
			(new CCheckBox('probe_snmp'))->setId('nm-probe-snmp')->setChecked(true)->setLabel('SNMP')
		]))->addClass('nm-field nm-checks'),
		$field(_('TCP ports'), $port_profile),
		$field(_('SNMP version'), $snmp_version),
		$field(_('SNMP communities'),
			(new CTextBox('communities', $data['communities'] !== '' ? $data['communities'] : 'public'))
				->setId('nm-communities')
				->setAttribute('autocomplete', 'off')
				->setAttribute('title', _('Comma separated, tried in order')),
			'nm-snmp-v12'
		),
		(new CDiv(
			(new CCheckBox('remember_communities'))
				->setId('nm-remember')
				->setChecked($data['remember_communities'])
				->setLabel(_('Remember communities'))
		))->addClass('nm-field nm-checks nm-snmp-v12'),
		$field(_('Security name'),
			(new CTextBox('v3_user'))->setId('nm-v3-user')->setAttribute('autocomplete', 'off'), 'nm-snmp-v3'
		),
		$field(_('Security level'), $v3_level, 'nm-snmp-v3'),
		$field(_('Auth protocol'), $v3_auth, 'nm-snmp-v3'),
		$field(_('Auth passphrase'),
			(new CPassBox('v3_auth_pass'))->setId('nm-v3-auth-pass')->setAttribute('autocomplete', 'new-password'),
			'nm-snmp-v3'
		),
		$field(_('Privacy protocol'), $v3_priv, 'nm-snmp-v3'),
		$field(_('Privacy passphrase'),
			(new CPassBox('v3_priv_pass'))->setId('nm-v3-priv-pass')->setAttribute('autocomplete', 'new-password'),
			'nm-snmp-v3'
		),
		$field(_('Context'),
			(new CTextBox('v3_context'))->setId('nm-v3-context')->setAttribute('autocomplete', 'off'), 'nm-snmp-v3'
		)
	]))->addClass('nm-row'),

	(new CDiv([
		(new CSimpleButton(_('Find neighbors of all switches')))->setId('nm-explore-all')->addClass(ZBX_STYLE_BTN_ALT),
		(new CSimpleButton(_('Auto layout')))->setId('nm-layout')->addClass(ZBX_STYLE_BTN_ALT),
		(new CSimpleButton(_('Fit')))->setId('nm-fit')->addClass(ZBX_STYLE_BTN_ALT),
		(new CSimpleButton(_('Export JSON')))->setId('nm-export')->addClass(ZBX_STYLE_BTN_ALT),
		(new CSimpleButton(_('Import JSON')))->setId('nm-import')->addClass(ZBX_STYLE_BTN_ALT),
		(new CSimpleButton(_('Save as Zabbix map')))->setId('nm-save-map')->addClass(ZBX_STYLE_BTN_ALT),
		(new CSimpleButton(_('Clear map')))->setId('nm-clear')->addClass(ZBX_STYLE_BTN_ALT),
		(new CSpan())->setId('nm-status')->addClass('nm-status')
	]))->addClass('nm-row nm-actions')
]))->addClass('nm-toolbar');

$content = (new CDiv([
	$toolbar,
	(new CDiv([
		(new CDiv())->setId('nm-canvas')->addClass('nm-canvas'),
		(new CDiv(
			(new CDiv(_('Scan a prefix, then select a device to see details and actions.')))->addClass('nm-hint')
		))->setId('nm-panel')->addClass('nm-panel')
	]))->addClass('nm-main'),
	(new CDiv())->setId('nm-log')->addClass('nm-log'),
	(new CDiv())->setId('nm-modal')->addClass('nm-modal-backdrop')->setAttribute('hidden', 'hidden')
]))->addClass('netmapper');

(new CHtmlPage())
	->setTitle($data['title'])
	->addItem($content)
	->show();

(new CScriptTag('view.init('.json_encode([
	'csrf_field' => CSRF_TOKEN_NAME,
	'csrf' => $data['csrf'],
	'groups' => $data['groups'],
	'templates' => $data['templates'],
	'vendor_profiles' => $data['vendor_profiles'],
	'fping' => $data['fping'],
	'snmp_ext' => $data['snmp_ext'],
	'max_targets' => $data['max_targets'],
	'chunk_size' => $data['chunk_size'],
	'userid' => CWebUser::$data['userid']
]).');'))
	->setOnDocumentReady()
	->show();
