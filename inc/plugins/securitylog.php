<?php
/**
 * Security Log
 * Copyright 2016 Starpaul20
 */

// Disallow direct access to this file for security reasons
if(!defined("IN_MYBB"))
{
	die("Direct initialization of this file is not allowed.<br /><br />Please make sure IN_MYBB is defined.");
}

// Tell MyBB when to run the hooks
$plugins->add_hook("datahandler_login_validate_end", "securitylog_run");
$plugins->add_hook("datahandler_user_delete_content", "securitylog_delete");

$plugins->add_hook("admin_user_users_merge_commit", "securitylog_merge");
$plugins->add_hook("admin_login_incorrect_pin", "securitylog_admin_pin");
$plugins->add_hook("admin_tools_menu_logs", "securitylog_admin_menu");
$plugins->add_hook("admin_tools_action_handler", "securitylog_admin_action_handler");
$plugins->add_hook("admin_tools_permissions", "securitylog_admin_permissions");
$plugins->add_hook("admin_tools_get_admin_log_action", "securitylog_admin_adminlog");

// The information that shows up on the plugin manager
function securitylog_info()
{
	global $lang;
	$lang->load("tools_securitylog");

	return array(
		"name"				=> $lang->securitylog_info_name,
		"description"		=> $lang->securitylog_info_desc,
		"website"			=> "http://galaxiesrealm.com/index.php",
		"author"			=> "Starpaul20",
		"authorsite"		=> "http://galaxiesrealm.com/index.php",
		"version"			=> "1.3",
		"codename"			=> "securitylog",
		"compatibility"		=> "18*"
	);
}

// This function runs when the plugin is installed.
function securitylog_install()
{
	global $db;
	securitylog_uninstall();
	$collation = $db->build_create_table_collation();

	switch($db->type)
	{
		case "pgsql":
			$db->write_query("CREATE TABLE ".TABLE_PREFIX."securitylog (
				uid int NOT NULL default '0',
				dateline numeric(30,0) NOT NULL default '0',
				admincp smallint NOT NULL default '0',
				ipaddress bytea NOT NULL default '',
				raw_username varchar(255),
			);");
			break;
		case "sqlite":
			$db->write_query("CREATE TABLE ".TABLE_PREFIX."securitylog (
				uid int NOT NULL default '0',
				dateline int NOT NULL default '0',
				admincp tinyint(1) NOT NULL default '',
				ipaddress blob(16) NOT NULL default '',
				raw_username varchar(255)
			);");
			break;
		default:
			$db->write_query("CREATE TABLE ".TABLE_PREFIX."securitylog (
				uid int unsigned NOT NULL default '0',
				dateline int unsigned NOT NULL default '0',
				admincp tinyint(1) NOT NULL default '0',
				ipaddress varbinary(16) NOT NULL default '',
				raw_username varchar(255),
				KEY uid (uid)
			) ENGINE=MyISAM{$collation};");
			break;
	}
}

// Checks to make sure plugin is installed
function securitylog_is_installed()
{
	global $db;
	if($db->table_exists("securitylog"))
	{
		return true;
	}
	return false;
}

// This function runs when the plugin is uninstalled.
function securitylog_uninstall()
{
	global $db;

	if($db->table_exists("securitylog"))
	{
		$db->drop_table("securitylog");
	}
}

// This function runs when the plugin is activated.
function securitylog_activate()
{
	change_admin_permission('tools', 'securitylog');
}

// This function runs when the plugin is deactivated.
function securitylog_deactivate()
{
	change_admin_permission('tools', 'securitylog', -1);
}

// Log bad login attempts
function securitylog_run($LoginDataHandler)
{
	global $db, $cache, $mybb;
	$mybb->binary_fields["securitylog"] = array('ipaddress' => true);

	if(count($LoginDataHandler->get_errors()) > 0 /*&& $LoginDataHandler->login_data['uid']*/)
	{
		if (!$LoginDataHandler->captcha_verified)
		{
			return;
		}

		$ipEscaped = $db->escape_string(get_ip());
		$ipBinaryEscaped = $db->escape_binary(my_inet_pton(get_ip()));

		$insert_array = array(
			"uid" => $LoginDataHandler->login_data['uid'] ?? 0,
			"dateline" => TIME_NOW,
			"admincp" => (int)defined('IN_ADMINCP'),
			"ipaddress" => $ipBinaryEscaped
		);

		if (($LoginDataHandler->login_data['uid'] ?? 0) == 0 && isset($LoginDataHandler->data['username'])) {
			$insert_array['raw_username'] = my_substr($LoginDataHandler->data['username'], 0, 255);
		}

		$db->insert_query('securitylog', $insert_array);

		// auto-ban
		$thresholds = [
			[
				'timespanSeconds' => 3600 * 24,
				'maxAttempts' => 20,
			],
		];
		$whitelist = [
		];

		if(!in_array(get_ip(), $whitelist))
		{
			foreach($thresholds as $threshold)
			{
				$cutoff = TIME_NOW - $threshold['timespanSeconds'];

				$query = $db->simple_select(
					'securitylog',
					'COUNT(*) AS n',
					'ipaddress=' . $ipBinaryEscaped . ' AND dateline > ' . $cutoff
				);
				$count = $db->fetch_field($query, 'n');

				if ($count > $threshold['maxAttempts'])
				{
					$query = $db->simple_select(
						'banfilters',
						'COUNT(*) AS n',
						"filter='" . $ipEscaped . "' AND type = 1"
					);
					$count = $db->fetch_field($query, 'n');

					if ($count == 0)
					{
						$insert_array = array(
							"type" => 1,
							"filter" => $ipEscaped,
							"dateline" => TIME_NOW
						);
						$db->insert_query('banfilters', $insert_array);

						$cache->update_bannedips();
					}
				}
			}
		}
	}
}

// Delete security log entries if user is deleted
function securitylog_delete($delete)
{
	global $db;

	$db->delete_query('securitylog', 'uid IN('.$delete->delete_uids.')');

	return $delete;
}

// Merge security log entries if users are merged
function securitylog_merge()
{
	global $db, $source_user, $destination_user;
	$uid = array(
		"uid" => $destination_user['uid']
	);
	$db->update_query("securitylog", $uid, "uid='{$source_user['uid']}'");
}

// Log bad login attempts with Admin CP pin
function securitylog_admin_pin()
{
	global $db, $mybb, $login_user;
	$mybb->binary_fields["securitylog"] = array('ipaddress' => true);

	$insert_array = array(
		"uid" => $login_user['uid'],
		"dateline" => TIME_NOW,
		"admincp" => 2,
		"ipaddress" => $db->escape_binary(my_inet_pton(get_ip()))
	);
	$db->insert_query('securitylog', $insert_array);
}

// Admin CP log page
function securitylog_admin_menu($sub_menu)
{
	global $lang;
	$lang->load("tools_securitylog");

	$sub_menu['140'] = array('id' => 'securitylog', 'title' => $lang->security_log, 'link' => 'index.php?module=tools-securitylog');

	return $sub_menu;
}

function securitylog_admin_action_handler($actions)
{
	$actions['securitylog'] = array('active' => 'securitylog', 'file' => 'securitylog.php');

	return $actions;
}

function securitylog_admin_permissions($admin_permissions)
{
	global $lang;
	$lang->load("tools_securitylog");

	$admin_permissions['securitylog'] = $lang->can_manage_security_log;

	return $admin_permissions;
}

// Admin Log display
function securitylog_admin_adminlog($plugin_array)
{
	global $lang;
	$lang->load("tools_securitylog");

	if($plugin_array['lang_string'] == 'admin_log_tools_securitylog_prune')
	{
		if($plugin_array['logitem']['data'][1])
		{
			$plugin_array['lang_string'] = 'admin_log_tools_securitylog_prune_user';
		}
	}

	return $plugin_array;
}