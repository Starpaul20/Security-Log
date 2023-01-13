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

$page->add_breadcrumb_item($lang->security_log, "index.php?module=tools-securitylog");

$sub_tabs['security_log'] = array(
	'title' => $lang->security_log,
	'link' => "index.php?module=tools-securitylog",
	'description' => $lang->security_log_desc
);
$sub_tabs['prune_security_log'] = array(
	'title' => $lang->prune_security_log,
	'link' => "index.php?module=tools-securitylog&amp;action=prune",
	'description' => $lang->prune_security_log_desc
);

if($mybb->input['action'] == 'prune')
{
	if($mybb->request_method == 'post')
	{
		$is_today = false;
		$mybb->input['older_than'] = $mybb->get_input('older_than', MyBB::INPUT_INT);
		if($mybb->input['older_than'] <= 0)
		{
			$is_today = true;
			$mybb->input['older_than'] = 1;
		}
		$where = 'dateline < '.(TIME_NOW-($mybb->input['older_than']*86400));

		// Searching for entries by a particular user
		if($mybb->input['uid'])
		{
			$where .= " AND uid='".$mybb->get_input('uid', MyBB::INPUT_INT)."'";
		}

		$db->delete_query("securitylog", $where);
		$num_deleted = $db->affected_rows();

		// Log admin action
		log_admin_action($mybb->input['older_than'], $mybb->input['uid'], $num_deleted);

		$success = $lang->success_pruned_security_logs;
		if($is_today == true && $num_deleted > 0)
		{
			$success .= ' '.$lang->note_logs_locked;
		}
		elseif($is_today == true && $num_deleted == 0)
		{
			flash_message($lang->note_logs_locked, 'error');
			admin_redirect("index.php?module=tools-securitylog");
		}
		flash_message($success, 'success');
		admin_redirect("index.php?module=tools-securitylog");
	}
	$page->add_breadcrumb_item($lang->prune_security_log, "index.php?module=tools-securitylog&amp;action=prune");
	$page->output_header($lang->prune_security_log);
	$page->output_nav_tabs($sub_tabs, 'prune_security_log');

	// Fetch filter options
	$sortbysel[$mybb->get_input('sortby')] = "selected=\"selected\"";
	$ordersel[$mybb->get_input('order')] = "selected=\"selected\"";

	$user_options[''] = $lang->all_users;
	$user_options['0'] = '----------';

	$query = $db->query("
		SELECT DISTINCT l.uid, u.username
		FROM ".TABLE_PREFIX."securitylog l
		LEFT JOIN ".TABLE_PREFIX."users u ON (l.uid=u.uid)
		ORDER BY u.username ASC
	");
	while($user = $db->fetch_array($query))
	{
		// Deleted Users
		if(!$user['username'])
		{
			$user['username'] = htmlspecialchars_uni($lang->na_deleted);
		}

		$user_options[$user['uid']] = htmlspecialchars_uni($user['username']);
	}

	$form = new Form("index.php?module=tools-securitylog&amp;action=prune", "post");
	$form_container = new FormContainer($lang->prune_security_log);
	$form_container->output_row($lang->username_colon, "", $form->generate_select_box('uid', $user_options, $mybb->get_input('uid'), array('id' => 'uid')), 'uid');
	if(!$mybb->get_input('older_than'))
	{
		$mybb->input['older_than'] = '60';
	}
	$form_container->output_row($lang->date_range, "", $lang->older_than.$form->generate_numeric_field('older_than', $mybb->get_input('older_than'), array('id' => 'older_than', 'style' => 'width: 50px', 'min' => 0)).' '.$lang->days, 'older_than');
	$form_container->end();
	$buttons[] = $form->generate_submit_button($lang->prune_security_log);
	$form->output_submit_wrapper($buttons);
	$form->end();

	$page->output_footer();
}

if(!$mybb->input['action'])
{
	$page->output_header($lang->security_log);

	$page->output_nav_tabs($sub_tabs, 'security_log');

	$perpage = $mybb->get_input('perpage', MyBB::INPUT_INT);
	if(!$perpage)
	{
		if(!$mybb->settings['threadsperpage'] || (int)$mybb->settings['threadsperpage'] < 1)
		{
			$mybb->settings['threadsperpage'] = 20;
		}
		
		$perpage = $mybb->settings['threadsperpage'];
	}

	$where = 'WHERE 1=1';

	// Searching for entries by a particular user
	if($mybb->get_input('uid') > 0)
	{
		$where .= " AND l.uid='".$mybb->get_input('uid', MyBB::INPUT_INT)."'";
	}

	if($mybb->get_input('ipaddress'))
	{
		$where .= " AND l.ipaddress=".$db->escape_binary(my_inet_pton($mybb->get_input('ipaddress')));
	}

	if($mybb->get_input('existing_accounts'))
	{
		$where .= " AND l.uid!=0";
	}

	// Order?
	switch($mybb->get_input('sortby'))
	{
		case "username":
			$sortby = "u.username";
			break;
		default:
			$sortby = "l.dateline";
	}
	$order = $mybb->get_input('order');
	if($order != "asc")
	{
		$order = "desc";
	}

	$query = $db->query("
		SELECT COUNT(l.dateline) AS count
		FROM ".TABLE_PREFIX."securitylog l
		{$where}
	");
	$rescount = $db->fetch_field($query, "count");

	// Figure out if we need to display multiple pages.
	if($mybb->get_input('page') != "last")
	{
		$pagecnt = $mybb->get_input('page', MyBB::INPUT_INT);
	}

	$postcount = (int)$rescount;
	$pages = $postcount / $perpage;
	$pages = ceil($pages);

	if($mybb->get_input('page') == "last")
	{
		$pagecnt = $pages;
	}

	if($pagecnt > $pages)
	{
		$pagecnt = 1;
	}

	if($pagecnt)
	{
		$start = ($pagecnt-1) * $perpage;
	}
	else
	{
		$start = 0;
		$pagecnt = 1;
	}

	$bannedIps = array_column(
		$cache->read('bannedips'),
		'filter'
	);

	$table = new Table;
	$table->construct_header($lang->username, array('width' => '30%'));
	$table->construct_header($lang->date, array("class" => "align_center", 'width' => '35%'));
	$table->construct_header($lang->ipaddress, array("class" => "align_center", 'width' => '20%'));
	$table->construct_header($lang->admin_attempt, array("class" => "align_center", 'width' => '15%'));
	$table->construct_header($lang->controls, array("class" => "align_center", 'width' => '1%'));

	$logitems = array();
	$query = $db->query("
		SELECT l.*, u.username, u.usergroup, u.displaygroup
		FROM ".TABLE_PREFIX."securitylog l
		LEFT JOIN ".TABLE_PREFIX."users u ON (u.uid=l.uid)
		{$where}
		ORDER BY {$sortby} {$order}
		LIMIT {$start}, {$perpage}
	");
	while($logitem = $db->fetch_array($query))
	{
		$logitems[] = $logitem;
	}

	$escapeCallbacks = [
		'ipaddress' => fn ($value) => $db->escape_binary($value),
		'uid' => 'intval',
		'raw_username' => fn ($value) => "'" . $db->escape_string($value) . "'",
	];
	$valueOccurrences = [];

	foreach($escapeCallbacks as $columnName => $escapeCallback)
	{
		$valueOccurrences[$columnName] = [];

		$values = array_column($logitems, $columnName);

		if($values)
		{
			$valuesEscaped = array_unique(
				array_map($escapeCallback, $values)
			);

			$query = $db->simple_select(
				'securitylog',
				$columnName . ' AS value, COUNT(*) AS n',
				$columnName . ' IN (' . implode(',', $valuesEscaped) . ')',
				[
					'group_by' => $columnName,
				],
			);

			while($item = $db->fetch_array($query))
			{
				$valueOccurrences[$columnName][ $item['value'] ] = $item['n'];
			}
		}
	}

	$i = 0;

	foreach($logitems as $logitem)
	{
		$i++;

		$date = my_date('relative', $logitem['dateline']);
		$trow = alt_trow();

		if($logitem['username'])
		{
			$username = format_name(htmlspecialchars_uni($logitem['username']), $logitem['usergroup'], $logitem['displaygroup']);
			$account = build_profile_link($username, $logitem['uid'], "_blank");

			$uidOccurrences = $valueOccurrences['uid'][ $logitem['uid'] ] ?? 0;
			if($uidOccurrences > 1)
			{
				$account .= ' <a href="index.php?module=tools-securitylog&uid=' . (int)$logitem['uid'] . '">(' . my_number_format((int)$uidOccurrences) . ')</a>';
			}
		}
		elseif($logitem['raw_username'])
		{
			if(my_strlen($logitem['raw_username']) > 30)
			{
				$shortUsername = htmlspecialchars_uni(
					my_substr($logitem['raw_username'], 0, 30)
				);
				$shortUsername .= '&hellip;';
			}
			else
			{
				$shortUsername = '<span data-autoselect>' . htmlspecialchars_uni($logitem['raw_username']) . '</span>';
			}

			$account = $logitem['username'] = '<i title="' . htmlspecialchars_uni($logitem['raw_username']) . '">' . $shortUsername . '</i>';

			$usernameOccurrences = $valueOccurrences['raw_username'][ $logitem['raw_username'] ] ?? 0;
			if($usernameOccurrences > 1)
			{
				$account .= ' (' . my_number_format((int)$usernameOccurrences) . ')';
			}
		}
		else
		{
			$account = htmlspecialchars_uni($lang->na_deleted);
		}

		$ipAddress = my_inet_ntop($db->unescape_binary($logitem['ipaddress']));
		$ipAddressDisplayed = '<span data-autoselect>' . $ipAddress . '</span>';
		if(in_array($ipAddress, $bannedIps))
		{
			$ipAddressDisplayed = '<s>' . $ipAddressDisplayed . '</s>';
		}
		$ipOccurrences = $valueOccurrences['ipaddress'][ $logitem['ipaddress'] ] ?? 0;
		if($ipOccurrences > 1)
		{
			$ipAddressDisplayed .= ' <a href="index.php?module=tools-securitylog&ipaddress=' . htmlspecialchars_uni($ipAddress) . '">(' . my_number_format((int)$ipOccurrences) . ')</a>';
		}

		if($logitem['admincp'] == 2)
		{
			$adminattempt = "<strong>{$lang->yes_pin}</strong>";
		}
		elseif($logitem['admincp'] == 1 && !empty($config['secret_pin']))
		{
			$adminattempt = "<strong>{$lang->yes_password}</strong>";
		}
		elseif($logitem['admincp'] == 1 && empty($config['secret_pin']))
		{
			$adminattempt = "<strong>{$lang->yes}</strong>";
		}
		else
		{
			$adminattempt = $lang->no;
		}

		$popup = new PopupMenu('entry_' . $i, $lang->options);
		$popup->add_item($lang->ban_ip_address, 'index.php?module=config-banning&type=ips&filter=' . $ipAddress);

		$table->construct_cell($account);
		$table->construct_cell($date, array("class" => "align_center"));
		$table->construct_cell($ipAddressDisplayed, array("class" => "align_center"));
		$table->construct_cell($adminattempt, array("class" => "align_center"));
		$table->construct_cell($popup->fetch(), array("class" => "align_center"));
		$table->construct_row();
	}

	if($table->num_rows() == 0)
	{
		$table->construct_cell($lang->no_security_logs, array("colspan" => "5"));
		$table->construct_row();
	}

	$table->output($lang->security_log);

	echo <<<'HTML'
	<script>
	document.querySelectorAll('[data-autoselect]').forEach($e => {
		$e.addEventListener('click', e => {
			let range = document.createRange();
			range.selectNodeContents($e);
			
			let selection = window.getSelection();
			selection.removeAllRanges();
			selection.addRange(range);
		});
	});
	</script>
	HTML;

	// Do we need to construct the pagination?
	if($rescount > $perpage)
	{
		echo draw_admin_pagination($pagecnt, $perpage, $rescount, "index.php?module=tools-securitylog&amp;perpage=$perpage&amp;uid={$mybb->get_input('uid', MyBB::INPUT_INT)}&amp;existing_accounts={$mybb->get_input('existing_accounts', MyBB::INPUT_INT)}&amp;sortby={$mybb->get_input('sortby', MyBB::INPUT_INT)}&amp;order={$order}")."<br />";
	}

	// Fetch filter options
	$sortbysel[$mybb->get_input('sortby')] = "selected=\"selected\"";
	$ordersel[$mybb->get_input('order')] = "selected=\"selected\"";

	$sort_by = array(
		'dateline' => $lang->date,
		'username' => $lang->username
	);

	$order_array = array(
		'asc' => $lang->asc,
		'desc' => $lang->desc
	);

	$form = new Form("index.php?module=tools-securitylog", "post");
	$form_container = new FormContainer($lang->filter_security_logs);
	$form_container->output_row(
		$lang->username_colon,
		"",
		$form->generate_text_box('uid', '', array('id' => 'uid')) .
		' / ' .
		$form->generate_check_box('existing_accounts', '1', '<a href="index.php?module=tools-securitylog&existing_accounts=1">' . $lang->existing_accounts . '</a>'),
		'uid'
	);
	$form_container->output_row($lang->ip_address_colon, "", $form->generate_text_box('ipaddress'), 'ipaddress');
	$form_container->output_row($lang->sort_by, "", $form->generate_select_box('sortby', $sort_by, $mybb->get_input('sortby'), array('id' => 'sortby'))." {$lang->in} ".$form->generate_select_box('order', $order_array, $order, array('id' => 'order'))." {$lang->order}", 'order');
	$form_container->output_row($lang->results_per_page, "", $form->generate_numeric_field('perpage', $perpage, array('id' => 'perpage', 'min' => 1)), 'perpage');

	$form_container->end();
	$buttons[] = $form->generate_submit_button($lang->filter_security_logs);
	$form->output_submit_wrapper($buttons);
	$form->end();

	// Autocompletion for usernames
	echo '
<link rel="stylesheet" href="../jscripts/select2/select2.css">
<script type="text/javascript" src="../jscripts/select2/select2.min.js?ver=1804"></script>
<script type="text/javascript">
<!--
$("#uid").select2({
	placeholder: "'.$lang->search_for_a_user.'",
	minimumInputLength: 2,
	multiple: false,
	ajax: { // instead of writing the function to execute the request we use Select2\'s convenient helper
		url: "../xmlhttp.php?action=get_users",
		dataType: \'json\',
		data: function (term, page) {
			return {
				query: term // search term
			};
		},
		results: function (data, page) { // parse the results into the format expected by Select2.
			data = data.map(e => { e.id = e.uid; return e; });
			return {results: data};
		}
	},
	initSelection: function(element, callback) {
		var query = $(element).val();
		if (query !== "") {
			$.ajax("../xmlhttp.php?action=get_users&getone=1", {
				data: {
					query: query
				},
				dataType: "json"
			}).done(function(data) { callback(data); });
		}
	}
});
// -->
</script>';

	$page->output_footer();
}
