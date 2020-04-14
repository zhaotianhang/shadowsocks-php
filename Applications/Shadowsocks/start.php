<?php
require_once 'config.php';
if($MODE === 'server') {
    require_once 'server.php';
    if($UDP_ENABLE) {
        require_once 'server_udp.php';
    }
} elseif($MODE === 'proxy') {
    require_once 'proxy.php';
}
else {
    require_once 'local.php';
}
