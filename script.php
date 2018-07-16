<?php

// ShareXen - Another ShareX Custom Uploader PHP Script

// Benchmark, do not touch
$start_time = microtime(true);


/**************************\
*    USER CONFIGURATION    *
* PLEASE READ THE COMMENTS *
\**************************/

/* MANDATORY CONSTANTS BELOW THIS LINE */

// Authentication tokens for users
// Never share a token with anyone else than the
// intended recipient, this can be very dangerous
// Set those to very long and random strings of
// various characters nobody can ever guess
define('USER_TOKENS', [
	'change-me', // Myself
	'change-me' // Friend
]);

// Allowed image extensions
define('EXTS', ['png', 'jpg', 'jpeg', 'gif', 'webm', 'mp4']);

// Deletion salt - NEVER SHARE THIS
// Used to generate and compute deletion hashes
// Changing this will render all previously generated
// deletion URLs invalid without any exception
// Keep empty to disable this feature, only admins will
// be able to delete files without deletion hashes
// Mandatory for having deletion URLs, set this to
// a very long and random string of various characters
define('DELETION_SALT', '');


/* OPTIONAL CONSTANTS BELOW THIS LINE */

// Amount of random characters in the generated filename
define('NAME_LENGTH', 7);

// Allow all users to upload / rename files
// with custom names instead of random ones
// Random names are still used if the
// filename parameter is unspecified
define('ALLOW_CUSTOM_NAMES', false);

// Admin users can rename / delete all files
// and upload with custom filenames independently
// of the above ALLOW_CUSTOM_NAMES parameter
// A user's ID is their token's position
// Every user ID under or equal to the specified
// value will be considered as an administrator
// Set to 0 to disable this feature altogether
define('MAX_ADMIN_ID', 0);

// Log requests to Discord using a webhook
// If you do not know what it is about, please ignore
// It is not recommended to set this if your API is heavily used
// By security, make sure the webhook outputs in a channel only you can see
// https://support.discordapp.com/hc/en-us/articles/228383668-Intro-to-Webhooks
define('DISCORD_WEBHOOK_URL', '');

// If the Discord webhook above is enabled,
// set this to false to stop logging bad requests
define('DISCORD_LOG_ERRORS', true);

// If the Discord webhook above is enabled,
// set this to false to embed logged image links
define('DISCORD_PREVENT_EMBED', true);


/* DANGEROUS CONSTANTS BELOW THIS LINE */

/***************************************\
* CHANGE THEM AT YOUR OWN RISK AND ONLY *
* IF YOU REALLY KNOW WHAT YOU ARE DOING *
\***************************************/

// Characters used to randomly generate the filename
// By security and to avoid breaking this application,
// do not use the following characters: / \ . : # ? &
// This isn't a comprehensive list of dangerous characters
define('KEYSPACE', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');

// Allow admin users to use custom filenames
// containing any character, thus ignoring the
// above keyspace entirely, which can be a huge
// security issue (e.g. path traversal)
// File extensions are still checked
define('ADMIN_IGNORE_KEYSPACE', false);

/*****************************\
*  END OF USER CONFIGURATION  *
* DO NOT TOUCH THE CODE BELOW *
\*****************************/


define('VERSION', 0.6);

$data = ['api_version' => VERSION];

if (version_compare(PHP_VERSION, '7.0.0', '<'))
{
	http_response_code(500);

	header('Content-Type: application/json; charset=utf-8');

	error_log('ShareXen v'.VERSION.': you need to use at least PHP 7.0'.
		' in order to run this script. You are running PHP '.PHP_VERSION);

	$data['http_code'] = 500;
	$data['status'] = 'error';
	$data['error'] = 'outdated_php_version';
	$data['debug'] = '7.0.0 > '.PHP_VERSION;

	die(json_encode($data));
}

function get_parameter($field)
{
	if (isset($_GET[$field]))
	{
		$result = $_GET[$field];

		if ($result)
		{
			return $result;
		}
	}

	if (isset($_POST[$field]))
	{
		return $_POST[$field];
	}
}

$endpoint = get_parameter('endpoint');
$data['endpoint'] = strval($endpoint) ?: 'unknown';

function check_auth($token)
{
	if (!isset($token) || $token === 'change-me')
	{
		return 0;
	}

	$uid = array_search($token, USER_TOKENS);
	if ($uid === false)
	{
		error_die($data, 403, 'invalid_credentials');
	}

	return ($uid + 1);
}
$data['user_id'] = check_auth($_POST['auth_token']);

function send_to_discord($msg)
{
	if (!defined('DISCORD_WEBHOOK_URL') || !DISCORD_WEBHOOK_URL)
	{
		return false;
	}

	if (!function_exists('curl_init'))
	{
		return false;
	}

	$c['content'] = '`['.date('H:i:s').']` '.$msg;

	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, DISCORD_WEBHOOK_URL);
	curl_setopt($ch, CURLOPT_POST, 1);
	curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, true);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
	curl_setopt($ch, CURLOPT_HEADER, true);
	curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($c));

	$r = curl_exec($ch);
	$r = json_decode($r, true);

	$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

	curl_close($ch);

	if ($code !== 204)
	{
		error_log('ShareXen Webhook Error: '.$r['message']);
		return false;
	}

	return true;
}

function log_request($data)
{
	$uid = $data['user_id'];

	$msg = '';

	if ($uid)
	{
		$msg .= 'Authenticated user #'.$uid.' ';
	}
	else
	{
		$msg .= 'Unauthenticated user ';
	}

	$endpoint = $data['endpoint'];
	$status = $data['error'] ?: $data['status'];
	$msg .= 'got a '.$data['http_code'].' ('.$status.') reponse '.
		'code, after calling the "'.$endpoint.'" endpoint.';

	$discord_logging = true;
	$discord_header = "\u{2705}";

	if ($status !== 'success')
	{
		if (defined('DISCORD_LOG_ERRORS') && DISCORD_LOG_ERRORS)
		{
			$discord_header = "\u{26A0}";
		}
		else
		{
			$discord_logging = false;
		}
	}
	else
	{
		switch ($endpoint) {
			case 'upload':
				$discord_header = "\u{1F517}";
				break;
			
			case 'delete':
				$discord_header = "\u{1F5D1}";
				break;

			case 'rename':
				$discord_header = "\u{1F4DD}";
				break;
		}
	}

	$url = isset($data['url']) ? $data['url'] : 0;

	if ($url)
	{
		$msg .= ' Generated URL: '.$url;
		if (isset($data['old_name']))
		{
			$msg .= ' (old name: '.$data['old_name'].')';
		}
	}
	elseif (isset($data['filename']))
	{
		$msg .= ' Target file: '.$data['filename'];
	}

	error_log('ShareXen v'.VERSION.': '.$msg);

	if ($discord_logging)
	{
		if (defined('DISCORD_PREVENT_EMBED') &&
			DISCORD_PREVENT_EMBED && $url)
		{
			$msg = str_replace($url, '<'.$url.'>', $msg);
		}

		send_to_discord($discord_header.' '.$msg);
	}
}

function end_request($data, $code = 200, $status = 'success')
{
	global $start_time;

	$data['http_code'] = $code;
	$data['status'] = $status;

	$data['execution_time'] = microtime(true) - $start_time;

	ob_start();

	http_response_code($code);

	header('Content-Type: application/json; charset=utf-8');
	header('Content-Encoding: none');

	echo(json_encode($data));

	header('Content-Length: '.ob_get_length());
	header('Connection: close');

	ob_end_flush();
	ob_flush();
	flush();

	log_request($data);

	die();
}

function error_die($data, $code, $reason = 'unknown_error', $debug = '')
{
	$data['error'] = $reason;

	if ($debug)
	{
		$data['debug'] = $debug;
	}

	end_request($data, $code, 'error');
}

if (!defined('KEYSPACE'))
{
	define('KEYSPACE', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
}

function get_deletion_hash($name)
{
	$salt = defined('DELETION_SALT')?DELETION_SALT:0;

	if (!$salt)
	{
		return false;
	}

	$filehash = hash_file('sha256', $name);
	return hash('sha256', $salt.$filehash.$name);
}

function enforce_auth($data)
{
	if ($data['user_id'] === 0)
	{
		error_die($data, 401, 'unauthenticated_request');
	}
}

function user_is_admin($data)
{
	if (!$data)
	{
		return false;
	}

	if (!defined('MAX_ADMIN_ID'))
	{
		define('MAX_ADMIN_ID', 0);
	}

	$uid = $data['user_id'];

	if (MAX_ADMIN_ID <= 0)
	{
		return false;
	}

	if ($uid === 0)
	{
		return false;
	}

	return ($uid <= MAX_ADMIN_ID);
}

function random_str($length = NAME_LENGTH, $keyspace = KEYSPACE)
{
	$pieces = [];
	$max = mb_strlen($keyspace, '8bit') - 1;

	for ($i = 0; $i < $length; ++$i) {
		$pieces []= $keyspace[random_int(0, $max)];
	}

	return implode('', $pieces);
}

function generate_all_urls(&$data)
{
	$https = $_SERVER['HTTPS'];
	$address = $_SERVER['SERVER_NAME'];
	$script = $_SERVER['SCRIPT_NAME'];
	$name = $data['filename'];

	$address = 'http'.($https?'s':'').'://'.$address;
	$sub = rtrim(dirname($script), '/').'/';

	$data['url'] = $address.$sub.$name;

	$hash = get_deletion_hash($name);
	if ($hash)
	{
		$data['deletion_hash'] = $hash;

		$data['deletion_url'] = $address.
			$script.'?endpoint=delete'.
			'&deletion_hash='.$hash.
			'&filename='.$name;
	}
}

function check_filename($name, $data)
{
	if (!$name)
	{
		return false;
	}

	$name = strval($name);

	$regex = '/^['.KEYSPACE.']+\.('.implode('|', EXTS).')$/';

	if (defined('ADMIN_IGNORE_KEYSPACE') &&
		ADMIN_IGNORE_KEYSPACE && user_is_admin($data))
	{
		$regex = '/^.+\.('.implode('|', EXTS).')$/';
	}

	if (!preg_match($regex, $name))
	{
		return false;
	}

	return true;
}

function get_custom_filename(&$data, $check = true, $field = 'filename')
{
	if ($check && !(defined('ALLOW_CUSTOM_NAMES') &&
		ALLOW_CUSTOM_NAMES) && !user_is_admin($data))
	{
		return false;
	}

	$filename = get_parameter($field);

	if (check_filename($filename, $data))
	{
		if ($check && file_exists($filename))
		{
			error_die($data, 403, 'file_already_exists');
		}

		return $filename;
	}
	elseif (isset($filename))
	{
		error_die($data, 403, 'forbidden_filename');
	}

	return false;
}

function ensure_file_exists(&$data, $name, $field = 'filename')
{
	if (!$name)
	{
		error_die($data, 400, 'missing_filename');
	}

	$data[$field] = $name;

	if (!file_exists($name))
	{
		error_die($data, 404, 'file_not_found');
	}
}

function ensure_file_access(&$data, $name, $restricted = true)
{
	$check_hash = !$restricted;

	if ($restricted) {
		$check_hash = defined('ALLOW_CUSTOM_NAMES') && ALLOW_CUSTOM_NAMES;
	}

	if (!file_exists($name) && $check_hash)
	{
		return;
	}

	if (user_is_admin($data))
	{
		$data['method'] = 'admin_user';
	}
	elseif ($check_hash)
	{
		$dh = get_parameter('deletion_hash');

		if (isset($dh))
		{
			$token = get_deletion_hash($name);

			if (!$token || $dh !== $token)
			{
				error_die($data, 403, 'invalid_deletion_hash');
			}

			$data['method'] = 'deletion_hash';
		}
	}

	if (!isset($data['method']))
	{
		error_die($data, 403, 'missing_permissions');
	}
}

function upload_image(&$data)
{
	enforce_auth($data);

	$file = $_FILES['image'];

	if (!isset($file))
	{
		error_die($data, 400, 'missing_file');
	}

	$regex = '/^('.implode('|', EXTS).')$/';
	$ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

	if (!isset($ext) || !preg_match($regex, $ext))
	{
		error_die($data, 415, 'invalid_file_extension');
	}

	$ext = '.'.$ext;

	$mime = mime_content_type($file['tmp_name']);
	if (!preg_match('/^(image|video)\//', $mime))
	{
		error_die($data, 415, 'invalid_file_mime_type');
	}

	if (!defined('NAME_LENGTH'))
	{
		define('NAME_LENGTH', 7);
	}

	$name = get_custom_filename($data);

	if (!$name)
	{
		$name = random_str().$ext;

		while (file_exists($name))
		{
			error_log('ShareXen Collision: File "'.$name.'" already exists.');
			$name = random_str().$ext;
		}
	}

	if (!move_uploaded_file($file['tmp_name'], $name))
	{
		error_die($data, 500, 'upload_failed');
	}

	$data['filename'] = $name;

	generate_all_urls($data);
}

$endpoints[] = 'upload';

function delete_image(&$data)
{
	$name = get_custom_filename($data, false);

	ensure_file_exists($data, $name);
	ensure_file_access($data, $name, false);

	if (!unlink($name))
	{
		error_die($data, 500, 'delete_failed');
	}
}

$endpoints[] = 'delete';

function rename_image(&$data)
{
	if (!(defined('ALLOW_CUSTOM_NAMES') &&
		ALLOW_CUSTOM_NAMES) && !user_is_admin($data))
	{
		error_die($data, 403, 'missing_permissions');
	}

	$old_name = get_custom_filename($data, false);

	ensure_file_exists($data, $old_name, 'old_name');
	ensure_file_access($data, $old_name);

	$new_name = get_custom_filename($data, true, 'new_name');

	if (!$new_name)
	{
		error_die($data, 400, 'missing_new_name');
	}

	if (!rename($old_name, $new_name))
	{
		error_die($data, 500, 'rename_failed');
	}

	$data['filename'] = $new_name;

	generate_all_urls($data);
}

$endpoints[] = 'rename';

if (!in_array($endpoint, $endpoints))
{
	error_die($data, 404, 'unknown_endpoint');
}

($endpoint.'_image')($data);

end_request($data);

?>
