<?php
namespace GDO\Security;

use GDO\Core\Application;
use GDO\Core\GDO_Module;
use GDO\Core\GDT_Checkbox;
use GDO\UI\GDT_Link;
use GDO\User\GDO_User;

/**
 * Alert on logins, when client has changes in IP or user agent.
 *
 * @version 6.10.3
 * @since 6.10.3
 * @author gizmore
 */
final class Module_Security extends GDO_Module
{

	public int $priority = 70;

	public function onLoadLanguage(): void
	{
		$this->loadLanguage('lang/security');
	}

	public function getUserSettings(): array
	{
		return [
			GDT_Link::make('link_security_access')->href(
				href('Security', 'Access')),
			GDT_Checkbox::make('sec_record_ip')->initial('0'),
			GDT_Checkbox::make('sec_uawatch')->initial('0'),
			GDT_Checkbox::make('sec_ipwatch')->initial('0'),
			GDT_Checkbox::make('sec_ispwatch')->initial('0'),
		];
	}

	public function getDependencies(): array
	{
		return [
			'Hash',
		];
	}

	public function getClasses(): array
	{
		return [
			GDO_AccountAccess::class,
		];
	}

	# ############
	# ## Hooks ###
	# ############
	public function hookUserAuthenticated(GDO_User $user)
	{
		if (!Application::instance()->isCLI())
		{
			GDO_AccountAccess::onAccess($user);
		}
	}

}
