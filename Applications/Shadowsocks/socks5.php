<?php

/**
 * 解析shadowsocks客户端发来的socket5头部数据
 * @param string $buffer
 */
function parse_socket5_header($buffer)
{
    /*
     * Shadowsocks TCP Relay Header:
     *
     *    +------+----------+----------+
     *    | ATYP | DST.ADDR | DST.PORT |
     *    +------+----------+----------+
     *    |  1   | Variable |    2     |
     *    +------+----------+----------+
     *
     */
    //检查长度
    if( strlen($buffer) < 1 ) {
        echo "invalid length for header\n";
        return false;
    }
    $addr_type = ord($buffer[0]);
    switch($addr_type)
    {
        case ADDRTYPE_IPV4:
            $header_length = 7;
            if(strlen($buffer) < $header_length) {
                echo "invalid length for ipv4 address\n";
                return false;
            }
            $dest_addr = ord($buffer[1]).'.'.ord($buffer[2]).'.'.ord($buffer[3]).'.'.ord($buffer[4]);
            $port_data = unpack('n', substr($buffer, 5, 2));
            $dest_port = $port_data[1];
            break;
        case ADDRTYPE_HOST:
            if( strlen($buffer) < 2 ) {
                echo "invalid length host name length\n";
                return false;
            }
            $addrlen = ord($buffer[1]);
            $header_length = $addrlen + 4;
            if(strlen($buffer) < $header_length) {
                echo "invalid host name length\n";
                return false;
            }
            $dest_addr = substr($buffer, 2, $addrlen);
            $port_data = unpack('n', substr($buffer, 2 + $addrlen, 2));
            $dest_port = $port_data[1];
            break;
        case ADDRTYPE_IPV6:
            // todo ...
            // ipv6 not support yet ...
            $header_length = 19;
            if(strlen($buffer) < $header_length) {
                echo "invalid length for ipv6 address\n";
                return false;
            }
            $dest_addr = inet_ntop(substr($buffer, 1, 16));
            $port_data = unpack('n', substr($buffer, 17, 2));
            $dest_port = $port_data[1];
            break;
        default:
            echo "unsupported addrtype $addr_type\n";
            return false;
    }
    return array($addr_type, $dest_addr, $dest_port, $header_length);
}

/*
 UDP 部分 返回客户端 头部数据 by @Zac
 //生成UDP header 它这里给返回解析出来的域名貌似给udp dns域名解析用的
*/
function pack_header($addr,$addr_type,$port){
    $header = '';
    //$ip = pack('N',ip2long($addr));
    //判断是否是合法的公共IPv4地址，192.168.1.1这类的私有IP地址将会排除在外
    /*
     if(filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE)) {
     // it's valid
     $addr_type = ADDRTYPE_IPV4;
     //判断是否是合法的IPv6地址
     }elseif(filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE)){
     $addr_type = ADDRTYPE_IPV6;
     }
     */
    switch ($addr_type) {
        case ADDRTYPE_IPV4:
            $header = b"\x01".inet_pton($addr);
            break;
        case ADDRTYPE_IPV6:
            $header = b"\x04".inet_pton($addr);
            break;
        case ADDRTYPE_HOST:
            if(strlen($addr)>255){
                $addr = substr($addr,0,255);
            }
            $header =  b"\x03".chr(strlen($addr)).$addr;
            break;
        default:
            return;
    }
    return $header.pack('n',$port);
}
