<?php

$file = @$_GET['file'] ?: '';

if (!$file) {
  http_response_code(400);
  die('No file specified.');
}

$regex = "/^[^\/.]+\.(png|jpe?g|gif|webp)$/";

if (!preg_match($regex, $file)) {
  http_response_code(400);
  die('Invalid filename.');
}

if (!file_exists($file)) {
  http_response_code(404);
  die('File not found.');
}

function human_filesize($bytes, $decimals = 2) {
  $sz = 'BKMGTP';
  $factor = floor((strlen($bytes) - 1) / 3);
  return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . @$sz[$factor] . 'B';
}

$size = human_filesize(filesize($file));

$url = 'http'.(isset($_SERVER['HTTPS']) ? 's' : '')."://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";

$pos = strpos($url, $_SERVER['PHP_SELF']);
if ($pos) {
  $url = substr($url, 0, $pos) . "/$file";
}

$url = explode('?', $url)[0].'?raw';

?>

<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8" />
  <title><?=$file?></title>

  <meta name="theme-color" content="#7289DA">
  <meta name="twitter:card" content="summary_large_image">
  <meta property="og:title" content="<?="$file ($size)"?>" />
  <meta property="og:image" content="<?=$url?>" />
</head>

<body>
  Metadata set, check HTML &lt;head&gt; for details.
</body>

</html>
