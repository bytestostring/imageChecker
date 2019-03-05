<?php

class ImageChecker {

private $log_file;
private $imageType, $imageBin, $f_context, $miniature, $first_bytes;
private $imageInfo = [];
private $mini = false;
private $max_bytes = 1024*1024*5;
private $max_resolution;
private $mem_cache_ttl = 1200;
private $mem, $current_bytes, $serialize_url, $link, $original_link;
private $mem_prefix = "img_";

function __construct()

{
	require('imageChecker.conf.php');
	$this->mem = new Memcached();
	if(!$this->mem->addServer($memcached['host'], $memcached['port'])) {
		$this->createError('Could not connect to Memcached');
		exit;
	}
	$this->mem_cache_ttl = $memcached['ttl'];
	$this->max_bytes = $max['size'];
	$this->max_resolution['width'] = $max['width'];
	$this->max_resolution['height'] = $max['height'];
	$this->miniature = $miniature;
	$this->log_file = __DIR__ ."/image_checker.log";
	$opts = [ 
		'http' => 
		['method' => 'GET', 'header' => "User-Agent: ImageChecker 0.3\r\n", 'max_redirects' => 3, 'protocol_version' => '1.1' ]

		];

	$this->f_context = stream_context_create($opts);

}

public function set_mini($opt)
{
	if ($opt) {
		$this->mini = true;
		$this->mem_prefix = "mini_";
	} else {
		$this->mem_prefix = "img_";
		$this->mini = false;
	}
	return true;

}

function getImageData(string &$source)

{
	if (!is_integer($this->imageType)) {
		return false;
	}
	$out = [];
	$ascii = &$source;
	$src_length = strlen($ascii);
	switch ($this->imageType):
	
		case '2':
		
		// Detect a jpeg type
		if ($ascii[6] == chr(0x4a) && $ascii[7] == chr(0x46) && $ascii[8] == chr(0x49) && $ascii[9] == chr(0x46) && $ascii[10] == chr(0x00)) {
			$out['subtype'] = 'JFIF';
		}

		// Find SOF0 marker of main image
		$i = 0;

		while ($i < $src_length-1):
			$sym = ord($ascii[$i]);
			if ($sym != 0xFF) {
				$i++;
				continue;	
			}
			$sym = ord($ascii[$i+1]);
			//Check APP1-APP15 and DQT markers
			if (($sym >= 224 && $sym <= 239) || $sym == 0xDB || $sym == 0xDD) {
				$len = ord($ascii[$i+2]) * 2**8  + ord($ascii[$i+3]);
				$i += $len+2;
				continue;
			}
				if ($sym == 0xC0) {
					$out['width'] = ord($ascii[$i+7]) * 2**8  + ord($ascii[$i+8]);
					$out['height'] = ord($ascii[$i+5]) * 2**8 + ord($ascii[$i+6]);
					break;
				}
			$i++;
		endwhile;
			
		break;
		case '3':
		// Detect IHDR marker
		if (!($ascii[12] == chr(0x49) && $ascii[13] == chr(0x48) && $ascii[14] == chr(0x44) && $ascii[15] == chr(0x52))) {
			return false;
		}
		
		// Get a resolution
		$out['width'] = ord($ascii[17]) * 2**16 + ord($ascii[18]) * 2**8 + ord($ascii[19]);
		$out['height'] = ord($ascii[21]) * 2**16 + ord($ascii[22]) * 2**8 + ord($ascii[23]);
	
		break;
	
	
		case '4':
		// Get a resolution
		$out['width'] = ord($ascii[7]) * 2**8 + ord($ascii[6]);
		$out['height'] = ord($ascii[9]) * 2**8 + ord($ascii[8]);
	
		break;
		case '5':
		// Detect a webp type
		if ($ascii[12] == chr(0x56) && $ascii[13] == chr(0x50) && $ascii[14] == chr(0x38)) {
			if ($ascii[15] == chr(0x58)) {
				$subtype = "VP8X";
			} elseif ($ascii[15] == chr(0x20)) {
				$subtype = "VP8";
			} else {
				return false;
			}
		} else {
			return false;
		}

		$out['subtype'] = $subtype;

		// Detect the size
		$out['size'] = ord($ascii[7]) * 2**24 + ord($ascii[6]) * 2**16 + ord($ascii[5]) *  2**8 + ord($ascii[4]) + 8;

		if ($subtype == "VP8") {
			
			$width = ord($ascii[27]) * 2**8 + ord($ascii[26]);
			$height = ord($ascii[29]) * 2**8 + ord($ascii[28]);
			if (is_integer($width) && is_integer($height)) {
				$out['width'] = $width;
				$out['height'] = $height;
			}
		} elseif ($subtype == "VP8X") {
			$width = ord($ascii[25]) * 2**8 + ord($ascii[24]);
			$height = ord($ascii[28]) * 2**8  + ord($ascii[27]);
			if (is_integer($width) && is_integer($height)) {
				$out['width'] = $width+1;
				$out['height'] = $height+1;
			}
		} else {
			return false;
		}

		if ($ascii[30] == chr(0x41) && $ascii[31] == chr(0x4e) && $ascii[32] == chr(0x49) && $ascii[33] == chr(0x4d)) {
			$out['animate'] = 1;
		} 
		break;
	endswitch;
	if (count($out) < 1) {
		return false;	
	}
	$this->imageInfo = array_merge((array)$out, (array) $this->imageInfo);
	return true;
}	
	
	
public function FastIdentifyImage($from_file = false)

{
	if (!$from_file) {
		$bytes = fread($this->link, 50);
		$this->first_bytes .= $bytes;
	} else {
		$bytes = $from_file;
	}

	$src_length = strlen($bytes);
	if ($src_length < 15) {
		return false;
	}
	
	$ascii = &$bytes;
	if ($ascii[0] == chr(0xff) && $ascii[1] == chr(0xd8) && $ascii[2] = chr(0xff)) {
		$this->imageType = 2;
		$this->imageInfo['mime'] = 'image/jpeg';
		return true;
	} elseif ($ascii[0] == chr(0x89) && $ascii[1] == chr(0x50) && $ascii[2] == chr(0x4e) && $ascii[3] == chr(0x47) 
			  && $ascii[4] == chr(0x0D) && $ascii[5] == chr(0x0A) && $ascii[6] == chr(0x1A) && $ascii[7] == chr(0x0A)) {
		$this->imageType = 3;
		$this->imageInfo['mime'] = 'image/png';
		return true;
	} elseif (($ascii[0] == chr(0x47) && $ascii[1] == chr(0x49) && $ascii[2] == chr(0x46) && $ascii[3] == chr(0x38) 
			   && $ascii[5] == chr(0x61)) AND ($ascii[4] == chr(0x37) || $ascii[4] == chr(0x39))) {
		$this->imageType = 4;
		$this->imageInfo['mime'] = 'image/gif';
		return true;
	} elseif (($ascii[0] == chr(0x52) && $ascii[1] == chr(0x49) && $ascii[2] == chr(0x46) && $ascii[3] == chr(0x46)) || 
			  ($ascii[8] == chr(0x57) && $ascii[9] == chr(0x45) && $ascii[10] == chr(0x42) && $ascii[11] == chr(0x50))) {
		$this->imageType = 5;
		$this->imageInfo['mime'] = 'image/webp';
		return true;
	} 

	$this->mem->set('err_' . $this->serialize_url, 'An error to identify a type', $this->mem_cache_ttl);
	$this->mem->set("lock_{$this->serialize_url}", 0, 30);
	$this->syslog("ImageType for {$this->serialize_url}: ".implode($b2h));
	return false;
}


public function setLink($link)

{
	$http_host = preg_quote($_SERVER['HTTP_HOST'], "/").preg_quote($_SERVER['SCRIPT_NAME'], "/");
	
	if (preg_match("/^http(s)?:\/\/".$http_host."/", $link) === 1) {
		$this->createError("Recursion is not allowed");
		return false;
	}
	$link_parse = parse_url($link);
	if (!isset($link_parse['scheme']) || !isset($link_parse['host']) || !isset($link_parse['path'])) {
		$this->createError("Incorrect link");
		return false;
	}
	$link_parse['host'] = idn_to_ascii($link_parse['host']);
	$url = filter_var($link_parse['host'], FILTER_VALIDATE_DOMAIN);
	if (!$url) {
		$this->createError("Incorrect link");
		return false;
        }
	$link = "{$link_parse['scheme']}://{$link_parse['host']}/".substr($link_parse['path'], 1);
	$this->serialize_url = md5($link);
	$this->original_link = $link;
	do {
		$img_lock_isset = $this->mem->get("lock_{$this->serialize_url}");
		if ($img_lock_isset === 1 ) {
			usleep(250000);
		}	
	} while ($img_lock_isset === 1);

		$err = $this->mem->get('err_' . $this->serialize_url);
		if ($err !== false) {
			$this->createError($err);
			return false;
		}
		$file = $this->mem->get("{$this->mem_prefix}{$this->serialize_url}");
		if ($file !== false) {
			if (!$this->FastIdentifyImage($file)) {
				$this->createError("Could not detect a file type.");
				exit;
			} else {
				$this->syslog("User has got a file from Memcached! YAY!");
				$this->imageBin = $file;
				$this->showImage();
				exit;
			}
		}

	if ($this->mem->set("lock_{$this->serialize_url}", 1, 30) !== false) {
		$this->syslog("User has locked the hash: [{$this->mem_prefix}] {$this->serialize_url}");
	}
	$f = @fopen($link, "rb", false, $this->f_context);
	if (!$f) {
		$this->mem->set("lock_{$this->serialize_url}", 0, 30);
		return false;
	}

	$this->link = $f;
	return true;
}

public function createError($err)

{
	$this->syslog($err);
	$width = round(strlen($err)*6.5);
	header('Content-Type: image/png');
	$im = imagecreatetruecolor($width, 20);
	$t_color = imagecolorallocate($im, 255, 255, 255);
	imagestring($im, 2, 2, 2, $err, $t_color);
	imagepng($im);
	exit(0);	
}

private function createMiniature()

{
	$min = &$this->miniature;
	$width = $this->imageInfo['width'];
	$height = $this->imageInfo['height'];
	if ($min['maxwidth'] < $width) {
	$delimiter_width = $width/$min['maxwidth'];
	}
	if ($min['maxheight'] < $height) {
	$delimiter_height = $height/$min['maxheight'];
	}
	if (isset($delimiter_height) && isset($delimiter_width)) {
		if ($delimiter_height >= $delimiter_width) {
			$main_delimiter = $delimiter_height;
		} else {
			$main_delimiter = $delimiter_width;
		}
	} elseif(isset($delimiter_width)) {
		$main_delimiter = $delimiter_width;
	} elseif(isset($delimiter_height)) {
		$main_delimiter = $delimiter_height;
	} else {
		$this->syslog("This image is a normal size"); 
		return true;
	}
	$new_width = $width/$main_delimiter;
	$new_height = $height/$main_delimiter;
	if ($this->imageType != 4 && $this->imageType != 5) {
		$mimg = imagecreatefromstring($this->imageBin);
		if (!$mimg) {
			return false;
		}
		$dimg = imagecreatetruecolor($new_width, $new_height);
		imagesavealpha($dimg, true);
		imagealphablending($dimg, false);
		$rs = imagecopyresampled($dimg, $mimg, 0, 0, 0, 0, $new_width, $new_height, $width, $height);
		if ($rs !== false) {
			return $dimg;
		} else {
			return false;
		}
	} elseif ($this->imageType == 4) {
		try {
			$gm = new GMagick();
			$gm->readimageblob($this->imageBin);
			$gm = $gm->coalesceimages();
			do {
				$gm->thumbnailimage($new_width, $new_height, Gmagick::FILTER_BOX, 1);
			} while ($gm->nextImage());
				$gm = $gm->deconstructImages();
				$ret = $gm->getimageblob();
		} catch (GmagickException $e) {
			$this->createError("An error [gif]");
			exit;
	
		}
			return $ret;
	} elseif ($this->imageType == 5) {
		try {
			$gm = new GMagick();
			$gm->readimageblob($this->imageBin);
			$gm->thumbnailimage($new_width, $new_height, Gmagick::FILTER_LANCZOS, 0.9);
			$ret = $gm->getimageblob();
		} catch (GmagickException $e) {
			$this->createError("An error [webp]");
			exit;
		}
			return $ret;	
	}
}

public function showImage()

{
	header("Cache-control: public, max-age=14400");
	header('Expires: '.gmdate('D, d M Y H:i:s \G\M\T', time() + (60 * 60 * 48)));
        switch ($this->imageType)
        {
                case '2':
                        header("Content-Type: image/jpeg");
                break;
                case '3':
                        header("Content-Type: image/png");
                break;
                case '4':
                        header("Content-Type: image/gif");
                break;
				case '5':
						header("Content-Type: image/webp");
				break;
        }
	if (!$this->mini) {
		echo $this->imageBin;
		exit;
	}
		$miniature = $this->createMiniature();
		if ($miniature !== true) {
			switch ($this->imageType) {
				case '2':
					imagejpeg($miniature);
				break;
				case '3':
					imagepng($miniature, null, 0, -1);
				break;
				case '4':
					echo $miniature;
				break;
				case '5':
					echo $miniature;
				break;
			}
			imagedestroy($miniature);
		} elseif ($miniature === true) {
			echo $this->imageBin;
		} else {
			$this->syslog("Could not create a miniature from imageType: {$this->ImageType}");
			echo $this->imageBin;
		}
	return true;
}

public function getImage()

{
	$bytes = 8192;
	$reads = 0;
	$file = $this->first_bytes;
	if ($this->imageType == 2) {
		while ($reads < $bytes*16 && !feof($this->link)) {
			$file .= fread($this->link, $bytes);
			$reads += $bytes;
		}
	} else {
		$file .= fread($this->link, $bytes);
		$reads += $bytes;
	}
	$idata = $this->getImageData($file);
	if (!$idata) {
		$this->mem->set("lock_{$this->serialize_url}", 0, 5);
		$this->mem->set('err_' . $this->serialize_url, 'Could not parse the image', $this->mem_cache_ttl);
		$this->createError("Could not parse the image");
		return false;
	} elseif (!isset($this->imageInfo['width']) || !isset($this->imageInfo['height'])) {
		$this->mem->set('err_' . $this->serialize_url, 'Could not detect the resolution', $this->mem_cache_ttl);
		$this->mem->set("lock_{$this->serialize_url}", 0, 5);
		$this->createError("Could not detect the resolution");
		return false;
	}
	if ($this->imageInfo['width'] > $this->max_resolution['width'] || $this->imageInfo['height'] > $this->max_resolution['height']) {
		$this->mem->set('err_' . $this->serialize_url, 'The resolution is too large', $this->mem_cache_ttl);
		$this->mem->set("lock_{$this->serialize_url}", 0, 5);
		$this->createError("The resolution is too large");
		return false;
	}
	while (!feof($this->link)):	
		$file .= fread($this->link, $bytes);
		$reads += $bytes;
	endwhile;
	$this->current_bytes = strlen($file);
	if ($reads > $this->max_bytes) {
		$this->mem->set('err_' . $this->serialize_url, 'File size is too large', $this->mem_cache_ttl);
		$this->mem->set("lock_{$this->serialize_url}", 0, 5);
		return false;
	}
	$this->imageBin = $file;
	$this->syslog("File \"{$this->original_link}\" has been downloaded. File size: {$this->current_bytes} bytes.");

	$miniature = $this->createMiniature();
	if ($miniature !== true && $miniature !== false) {
		$stream = fopen("php://memory", "w+");
		if ($stream) {
			switch ($this->imageType) {
				case '2':
					imagejpeg($miniature, $stream);
				break;
				case '3':
					imagepng($miniature, $stream);
				break;
				case '4':
					$mini = $miniature;
				break;
				case '5':
					$mini = $miniature;
				break;
			}
				if ($this->imageType != 4 && $this->imageType != 5) {
					rewind($stream);
					$mini = stream_get_contents($stream);
				}	

			if ($this->mem->set("mini_{$this->serialize_url}", $mini, $this->mem_cache_ttl) !== false) {
				$this->syslog("A file with hash [mini_ by {$this->mem_prefix}] \"{$this->serialize_url}\" has been cached in {$this->mem_cache_ttl} seconds");
			} else {
				$this->syslog("Error code" .$this->mem->getResultCode());
			}
		}
	}

	if ($this->mem->set("img_{$this->serialize_url}", $file, $this->mem_cache_ttl) !== false) {
		$this->syslog("A file with hash [img_ by {$this->mem_prefix}] \"{$this->serialize_url}\" has been cached in Memcached in {$this->mem_cache_ttl} seconds");	
	} else {
		$this->syslog("Error code: ".$this->mem->getResultCode());
	}
	if ($this->mem->set("lock_{$this->serialize_url}", 0, 5) !== false) {
		$this->syslog("User has unlocked the hash: {$this->serialize_url}");
	}
	return true;
}

public function syslog($text)

{
	$f = fopen($this->log_file, "a+");
	if (!$f) {
		return false;
	}
	flock($f, LOCK_EX);
	fwrite($f, "[{$_SERVER['REMOTE_ADDR']}] - [". date('d/M/Y:H:i:s'). "] {$text}\n");
	flock($f, LOCK_UN);
	fclose($f);
	return true;
}

 }

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

