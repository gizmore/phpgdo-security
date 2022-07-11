<?php
namespace GDO\Security;

use GDO\Core\GDO;
use GDO\Core\GDT_AutoInc;
use GDO\Core\GDT_CreatedAt;
use GDO\Mail\Mail;
use GDO\Net\GDT_IP;
use GDO\Core\GDT_MD5;
use GDO\UI\GDT_Link;
use GDO\User\GDT_User;
use GDO\User\GDO_User;
use GDO\DB\GDT_Index;

/**
 * Table with user login history.
 * Alerts user on suspicous change of IP / InternetServiceProvider / UserAgent
 * 
 * @author gizmore
 * @version 6.10.3
 * @since 3.0.0
 * 
 * @see User
 * @see GDO_AccountSetting
 */
final class GDO_AccountAccess extends GDO
{
	public function gdoCached() : bool { return false; }
	
	###########
	### GDO ###
	###########
	public function gdoColumns() : array
	{
		return [
			GDT_AutoInc::make('accacc_id'),
			GDT_User::make('accacc_uid'),
			GDT_MD5::make('accacc_ua')->notNull(),
			GDT_IP::make('accacc_ip')->notNull(),
			GDT_MD5::make('accacc_isp'),
			GDT_CreatedAt::make('accacc_time'),
		    GDT_Index::make('user_index')->indexColumns('accacc_uid')->hash(),
		];
	}

	/**
	 * On authentication, check the old history against current data.
	 * Mail on suspicous activity.
	 * Add a new entry.
	 * @param GDO_User $user
	 */
	public static function onAccess(GDO_User $user)
	{
	    $module = Module_Security::instance();
		
		$query = '';
		
		# Check UA
		$ua = self::uahash();
		if ($module->settingValue('sec_uawatch'))
		{
			$query .= " AND ".self::hash_check('accacc_ua', $ua);
		}
		
		# Check exact IP
		$ip = GDT_IP::current();
		if ($module->settingValue('sec_ipwatch'))
		{
			$query .= " AND accacc_ip=".GDO::quoteS($ip);
		}
		
		# Check ISP
		$isp = null;
		if ($module->settingValue('sec_ispwatch'))
		{
			$isp = self::isphash();
			$query .= ' AND '.self::hash_check('accacc_isp', $isp);
		}
		
		# Query alert
		if (!empty($query))
		{
			if (0 != self::table()->countWhere("accacc_uid={$user->getID()}"))
			{
				if (!self::table()->select('1')->where("accacc_uid={$user->getID()} $query")->exec()->fetchValue())
				{
					self::sendAlertMail($user);
				}
			}
		}
		
		if ($module->settingValue('sec_record_ip'))
		{
			# New access insert
			self::blank([
				'accacc_uid' => $user->getID(),
				'accacc_ua' => $ua,
				'accacc_ip' => $ip,
				'accacc_isp' => $isp,
			])->insert();
		}
	}
	
	private static function isphash()
	{
		if (GDT_IP::current() === ($isp = @gethostbyaddr(@$_SERVER['REMOTE_ADDR'])))
		{
			$isp = null;
		}
		return self::hash($isp);
	}
	
	private static function uahash()
	{
		return self::hash(preg_replace('/\d/', '', $_SERVER['HTTP_USER_AGENT']));
	}
	
	private static function hash_check($field, $hash, $quote='"')
	{
		return $hash === null ? $field.' IS NULL' : $field.'='.quote($hash);
	}
	
	private static function hash($value)
	{
		return $value === null ? null : md5($value, true);
	}
	
	public static function sendAlertMail(GDO_User $user)
	{
		if ($receive_mail = $user->getMail())
		{
			$mail = new Mail();
			$mail->setSender(GDO_BOT_EMAIL);
			$mail->setSenderName(GDO_BOT_NAME);
			$mail->setReceiver($receive_mail);
			$mail->setSubject(t("mail_subj_account_alert", [sitename()]));
			$mail->setBody(t("mail_body_account_alert", array(
				$user->renderUserName(),
				sitename(),
				html($_SERVER['HTTP_USER_AGENT']),
				$_SERVER['REMOTE_ADDR'],
				gethostbyaddr($_SERVER['REMOTE_ADDR']),
				GDT_Link::anchor(url('Security', 'Access')),
				GDT_Link::anchor(url('Account', 'Settings', '&module=Security')),
			)));
			$mail->sendToUser($user);
		}
	}
	
}
