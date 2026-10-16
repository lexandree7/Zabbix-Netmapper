<?php declare(strict_types = 0);
/*
** Network mapper - Zabbix 7.0 LTS frontend module.
**
** Registers the "Monitoring > Network mapper" menu entry. Access to the module can additionally be
** restricted per user role (Users > User roles > Access to UI elements > Modules).
*/


namespace Modules\NetMapper;

use APP,
	CMenuItem,
	Zabbix\Core\CModule;

class Module extends CModule {

	public function init(): void {
		APP::Component()->get('menu.main')
			->findOrAdd(_('Monitoring'))
				->getSubmenu()
					->insertAfter(_('Discovery'),
						(new CMenuItem(_('Network mapper')))->setAction('netmapper.view')
					);
	}
}
