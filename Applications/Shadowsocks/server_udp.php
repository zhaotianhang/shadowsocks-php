<?php

use \Workerman\Worker;
use \Workerman\Connection\AsyncUdpConnection;
use \Workerman\Autoloader;

// 自动加载类
require_once __DIR__ . '/../../Workerman/Autoloader.php';
require_once __DIR__.'/config.php';
require_once __DIR__.'/socks5.php';
Autoloader::setRootPath(__DIR__);

// UDP support
$worker_udp = new Worker('udp://0.0.0.0:'. $PORT);
$worker_udp->count = 1;
$worker_udp->name = 'shadowsocks-server';

/*
 * todo: UDP部分暂时有一些问题
 */
$worker_udp->onMessage = function($connection, $buffer)use($METHOD, $PASSWORD)
{
    $encryptor = new Encryptor($PASSWORD, $METHOD, true);
    $buffer = $encryptor->decrypt($buffer);
    // 解析socket5头
    $header_data = parse_socket5_header($buffer);
    // 解析头部出错，则关闭连接
    if(!$header_data)
    {
        $connection->close();
        return;
    }
    // 头部长度
    $header_len = $header_data[3];
    $host = $header_data[1];
    $port = $header_data[2];
    $address = "udp://$host:$port";

    $remote_connection = new AsyncUdpConnection($address);
    @$remote_connection->source = $connection;
    $remote_connection->onConnect = function($remote_connection)use($buffer, $header_len)
    {
        $remote_connection->send(substr($buffer,$header_len));
    };
    $remote_connection->onMessage = function($remote_connection, $buffer)use($header_data, $METHOD, $PASSWORD)
    {
        $_header = pack_header($header_data[1], $header_data[0], $header_data[2]);
        $encryptor = new Encryptor($PASSWORD, $METHOD, true);
        $_data = $encryptor->encrypt($_header . $buffer);
        $remote_connection->source->send($_data);
    };
    $remote_connection->connect();
};

// 如果不是在根目录启动，则运行runAll方法
if(!defined('GLOBAL_START'))
{
    Worker::runAll();
}
