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
$plugins->add_hook("datahandler_login_verify_password_end", "securitylog_run");

$plugins->add_hook("admin_login_incorrect_pin", "securitylog_admin_pin");
$plugins->add_hook("admin_tools_menu_logs", "securitylog_admin_menu");
$plugins->add_hook("admin_tools_action_handler", "securitylog_admin_action_handler");
$plugins->add_hook("admin_tools_permissions", "securitylog_admin_permissions");

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
		"version"			=> "1.0",
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
				ipaddress bytea NOT NULL default ''
			);");
			break;
		case "sqlite":
			$db->write_query("CREATE TABLE ".TABLE_PREFIX."securitylog (
				uid int NOT NULL default '0',
				dateline int NOT NULL default '0',
				admincp tinyint(1) NOT NULL default '',
				ipaddress blob(16) NOT NULL default ''
			);");
			break;
		default:
			$db->write_query("CREATE TABLE ".TABLE_PREFIX."securitylog (
				uid int unsigned NOT NULL default '0',
				dateline int unsigned NOT NULL default '0',
				admincp tinyint(1) NOT NULL default '0',
				ipaddress varbinary(16) NOT NULL default '',
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
function securitylog_run($args)
{
	global $db, $mybb, $user;
	$mybb->binary_fields["securitylog"] = array('ipaddress' => true);

	if(defined('IN_ADMINCP'))
	{
		$admincp = 1;
		$password = md5($mybb->input['password']);
	}
	else
	{
		$admincp = 0;
		$password = md5($user['password']);
	}

	$saltedpassword = md5(md5($args['this']->login_data['salt']).$password);
	if($saltedpassword !== $args['this']->login_data['password'])
	{
		$insert_array = array(
			"uid" => $args['this']->login_data['uid'],
			"dateline" => TIME_NOW,
			"admincp" => $admincp,
			"ipaddress" => $db->escape_binary(my_inet_pton(get_ip()))
		);
		$db->insert_query('securitylog', $insert_array);
	}

	return $args;
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

?>