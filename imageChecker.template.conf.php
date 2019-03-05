<?php
// This file must be renamed to imageChecker.conf.php

// Memcached server params
$memcached = ['host' => '%HOST%', 'port' => 0, 'ttl' => 1200];

// max. image size
$max = [ 'size' => 1024*1024*5, 'width' => 8192, 'height' => 8192 ];

// max. miniature size
$miniature = [ 'maxwidth' => 165, 'maxheight' => 125 ];

?>
