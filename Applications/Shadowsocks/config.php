<?php

// 模式，支持server、local
$MODE = 'server';
// 启用UDP协议
// 不支持windows系统，需要fork函数
$UDP_ENABLE = false;
// 服务器地址
$SERVER = '127.0.0.1';
// 服务器端口
$PORT = 443;
// 加密算法
$METHOD = 'aes-256-cfb';
// 密码
$PASSWORD = '12345678';
// 协议
$PROTOCOL = 'auth_aes128_md5';
// auth_aes128_×xx 协议参数
$PROTOCOL_PARAM_AUTH_AES128 = array(
	'1:password',  //client仅使用第一个参数连接
	'2:password',
	'3:password',
);
// 协议参数
$PROTOCOL_PARAM = $PROTOCOL_PARAM_AUTH_AES128;
// 客户端端口
$LOCAL_PORT = 1080;
// 启动多少进程
$PROCESS_COUNT = 2;
