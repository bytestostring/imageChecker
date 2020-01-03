<?php
// Example of usage the script
// https://yourhost.com/imageChecker?url={image_url} or
// https://yourhost.com/imageChecker?mini=1&url={image_url} to get a miniature of image.
	include('imageChecker.class.php');
	if (!isset($_GET['url'])) {
		http_response_code(403);
		exit;
	}
	$url = strip_tags($_GET['url']);
	$ich = new ImageChecker;
	if (isset($_GET['mini'])) {
		$ich->set_mini(true);
	}

	if (!isset($err)) {
		if (!$ich->setLink($url)) {
			$err = "An error to get the image";
		}
	}
	if (!isset($err)) {
		if (!$ich->FastIdentifyImage()) {
			$err = "An error to identify a type";
		}
	}
	if (!isset($err)) {
		if (!$ich->getImage()) {
			$err = "File size is too large";
		}
	}

	if (isset($err)) {
		$ich->createError($err);
		exit;
	}
		$ich->showImage();
    
?>

