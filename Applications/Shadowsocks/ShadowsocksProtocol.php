<?php

/**
 * 协议类
 * 处理明文数据
 * @author hxdyxd<hxdyxd@gmail.com>
 */
class ShadowsocksProtocol
{
    protected $_protocol;
    protected static $_protocolSupported = array(
        'origin',
        'auth_aes128_md5',
        'auth_aes128_sha1',
    );

    public function __construct($key, $iv, $protocol, $param)
    {
        switch($protocol) {
            case 'auth_aes128_md5':
            case 'auth_aes128_sha1':
                $this->_protocol = new AuthAesProtocol($key, $iv, $protocol, $param);
                break;
            case 'origin':
            default:
                $this->_protocol = new OriginProtocol();
                break;
        }
    }

    //客户端发送到服务端数据加密前
    public function ClientPreEncrypt($plaindata)
    {
        return $this->_protocol->ClientPreEncrypt($plaindata);
    }

    //客户端收到服务端数据解密后
    public function ClientPostDecrypt($plaindata)
    {
        return $this->_protocol->ClientPostDecrypt($plaindata);
    }

    //服务端发送到客户端数据加密前
    public function ServerPreEncrypt($plaindata)
    {
        return $this->_protocol->ServerPreEncrypt($plaindata);
    }

    //服务端收到客户端数据解密后
    public function ServerPostDecrypt($plaindata)
    {
        return $this->_protocol->ServerPostDecrypt($plaindata);
    }

    public function ClientUdpPreEncrypt($plaindata)
    {
        return $plaindata;
    }

    public function ClientUdpPostDecrypt($plaindata)
    {
        return $plaindata;
    }

    public function ServerUdpPreEncrypt($plaindata)
    {
        return $plaindata;
    }

    public function ServerUdpPostDecrypt($plaindata)
    {
        return $plaindata;
    }
}


class OriginProtocol
{
    public function __construct()
    {
        echo "OriginProtocol \n";
    }

    //客户端发送到服务端数据加密前
    public function ClientPreEncrypt($plaindata)
    {
        return $plaindata;
    }

    //客户端收到服务端数据解密后
    public function ClientPostDecrypt($plaindata)
    {
        return $plaindata;
    }

    //服务端发送到客户端数据加密前
    public function ServerPreEncrypt($plaindata)
    {
        return $plaindata;
    }

    //服务端收到客户端数据解密后
    public function ServerPostDecrypt($plaindata)
    {
        return $plaindata;
    }
}


class AuthAesProtocol
{
    protected $_hashfunc;
    protected $_key;
    protected $_recv_iv;
    protected $_protocol;
    protected $_param;
    protected $_recv_buf;
    protected $_has_recv_header;
    protected $_has_send_header;
    protected $_recv_id;
    protected $_pack_id;
    protected $_user_key;
    protected $_user_id;
    protected static $_padding_data = true;
    protected static $_server_info = array(
        'data' => array(
            'connection_id' => 0xffffffff,
            'connection_num' => 0,
            'local_client_id' => 'abcd',
        ),
    );
    protected static $_max_time_dif = 86400;
    protected static $_unit_len = 8100;
    protected static $_protocolSupported = array(
        'auth_aes128_md5' => 'md5',
        'auth_aes128_sha1' => 'sha1',
    );

    public function __construct($key, $iv, $protocol, $param)
    {
        assert(is_array($param), "\$param type error\n");
        assert(is_string($protocol), "\$protocol type error\n");
        assert(is_string($iv), "\$iv type error\n");
        assert(is_string($key), "\$key type error\n");

        $this->_key = $key;
        $this->_recv_iv = $iv;
        $this->_protocol = $protocol;
        $this->_hashfunc = self::$_protocolSupported[$this->_protocol];
        $this->_param = array();
        if( count($param) === 0) {
            $this->_user_key = $key;
            $this->_user_id = rand(0, 0x7fffffff);
        } else {
            foreach ($param as $value) {
                $t = explode(':', $value);
                $this->_param[$t[0]] = $t[1];
                if(!isset($this->_user_id)) {
                    $this->_user_id = $t[0];
                }
            }
            $this->_user_key = hash($this->_hashfunc, $this->_param[$this->_user_id], true);
        }
        $this->_recv_buf = '';
        $this->_has_recv_header = false;
        $this->_has_send_header = false;
        $this->_recv_id = 1;
        $this->_pack_id = 1;
        if(self::$_server_info['data']['connection_id'] == 0xffffffff) {
            self::$_server_info['data']['connection_id'] = rand(0, 0xFFFFFF);
            self::$_server_info['data']['local_client_id'] = openssl_random_pseudo_bytes(4);
            echo "Set client id: " . bin2hex(self::$_server_info['data']['local_client_id']) . "\n";
        }
        $conn_num = ++self::$_server_info['data']['connection_num'];
        $cid = bin2hex(self::$_server_info['data']['local_client_id']);
        echo "AuthAesProtocol $this->_protocol uid:$this->_user_id cid:$cid con:$conn_num\n";
    }

    //客户端发送到服务端数据加密前
    public function ClientPreEncrypt($plaindata)
    {
        $out_buf = '';
        $ogn_data_len = strlen($plaindata);
        if(!$this->_has_send_header) {
            $head_len = $this->get_head_size($plaindata, 30);
            $head_len = min( strlen($plaindata), $head_len + rand(0, 31));
            $out_buf .= $this->pack_auth_data($this->auth_data(), substr($plaindata, 0, $head_len));
            $plaindata = substr($plaindata, $head_len);
            $this->_has_send_header = true;
        }

        while(strlen($plaindata) > self::$_unit_len) {
            $out_buf .= $this->pack_data(substr($plaindata, 0, self::$_unit_len));
            $plaindata = substr($plaindata, self::$_unit_len);
        }
        $out_buf .= $this->pack_data($plaindata);
        $this->_last_rnd_len = $ogn_data_len;
        return $out_buf;
    }

    //客户端收到服务端数据解密后
    public function ClientPostDecrypt($plaindata)
    {
        $this->_recv_buf .= $plaindata;
        $out_buf = '';
        while( strlen($this->_recv_buf) > 4 ) {
            $hmac_key = $this->_user_key . pack('V', $this->_recv_id);
            $this_my = hash_hmac($this->_hashfunc, substr($this->_recv_buf, 0, 2), $hmac_key, true);
            $this_my = substr($this_my, 0, 2);
            if( substr($this->_recv_buf, 2, 2) !== $this_my) {
                if($this->_recv_id === 0) {
                    echo "over size\n";
                    return 'eeeeeeeeeeeeeee';
                } else {
                    echo "server_post_decrype data error\n";
                    return 'eeeeeeeeeeeeeee';
                }
            }
            $block_size = unpack('v1plen', substr($this->_recv_buf, 0, 2) );
            $block_size = $block_size['plen'];
            if($block_size >= 8192 || $block_size < 7) {
                $this->recv_buf = '';
                if($this->_recv_id === 0) {
                    echo "over size\n";
                    return 'eeeeeeeeeeeeeee';
                } else {
                    echo "server_post_decrype data length error\n";
                    return 'eeeeeeeeeeeeeee';
                }
            }
            if( strlen($this->_recv_buf) < $block_size) {
                break;
            }

            //echo $block_size . " <-- block_size\n";
            $block = substr($this->_recv_buf, 0, $block_size);
            $this->_recv_buf = substr($this->_recv_buf, $block_size);
            $this_my = hash_hmac($this->_hashfunc, substr($block, 0, $block_size-4), $hmac_key, true);
            $this_my = substr($this_my, 0, 4);
            if( substr($block, -4) !== $this_my) {
                $this->recv_buf = '';
                if($this->_recv_id === 0) {
                    echo "over size\n";
                    return 'eeeeeeeeeeeeeee';
                } else {
                    echo "server_post_decrype data checksum error\n";
                    return 'eeeeeeeeeeeeeee';
                }
            }

            $this->_recv_id = ($this->_recv_id + 1) & 0xFFFFFFFF;
            $pos = ord($block[4]);
            if($pos == 255) {
                $pos = (ord($block[5]) | ord($block[6])<<8);
            }
            $out_buf .= substr($block, $pos + 4, $block_size - 4 - $pos - 4);
        }

        return $out_buf;
    }

    //服务端发送到客户端数据加密前
    public function ServerPreEncrypt($plaindata)
    {
        $out_buf = '';
        $ogn_data_len = strlen($plaindata);
        while( strlen($plaindata) > self::$_unit_len) {
            $out_buf .= $this->pack_data(substr($plaindata, 0, self::$_unit_len));
            $plaindata = substr($plaindata, self::$_unit_len);
        }
        $out_buf .= $this->pack_data($plaindata);
        $this->_last_rnd_len = $ogn_data_len;
        return $out_buf;
    }

    //服务端收到客户端数据解密后
    public function ServerPostDecrypt($plaindata)
    {
        $this->_recv_buf .= $plaindata;
        $out_buf = '';

        if(!$this->_has_recv_header) {
            if(strlen($this->_recv_buf) >= 7) {
                $hmac_key = $this->_recv_iv . $this->_key;

                $part1 = substr($this->_recv_buf, 0, 7);
                $part1_my = hash_hmac($this->_hashfunc, $part1[0], $hmac_key, true);
                $part1_my = substr($part1_my, 0, 6);
                if( substr($part1, -6) !== $part1_my) {
                    echo "part1 data uncorrect auth HMAC-SHA1\n";
                    return false;
                }
            }
            if(strlen($this->_recv_buf) < 31) {
                //need more
                return false;
            }
            //---------------------------------------------------------------------
            $part2 = substr($this->_recv_buf, 7, 24);
            $part2_my = hash_hmac($this->_hashfunc, substr($part2, 0, 20), $hmac_key, true);
            $part2_my = substr($part2_my, 0, 4);
            if( substr($part2, -4) !== $part2_my) {
                echo "part2 data uncorrect auth HMAC-SHA1\n";
                return false;
            }

            $uid_data = substr($part2, 0, 4);
            $uid = unpack('V1uid', $uid_data);

            $this->_user_id = $uid['uid'];
            if( !isset($this->_param[$this->_user_id])) {
                if( count($this->_param) === 0) {
                    $this->_user_key = $this->_key;
                } else {
                    echo "user id is unknow\n";
                    return false;
                }
            } else {
                $this->_user_key = hash($this->_hashfunc, $this->_param[$this->_user_id], true);
            }
            echo 'user id:' . $this->_user_id . "\n";

            $part2_enc_part_key = md5(base64_encode($this->_user_key) . $this->_protocol, true);
            $part2_enc_part = substr($part2, 4, 16);
            $part2_enc_part = $this->decrypt_no_bug($part2_enc_part, $part2_enc_part_key);
            if( strlen($part2_enc_part) != 16 ) {
                echo "user key error\n";
                return false;
            }
            //---------------------------------------------------------------------
            $aes_enc_part = unpack('V1utc/V1cid/V1conid/v1plen/v1rlen', $part2_enc_part);
            //var_dump($aes_enc_part);
            if( strlen($this->_recv_buf) < $aes_enc_part['plen'] ) {
                //need more
                return false;
            }

            $handshake_my = hash_hmac($this->_hashfunc, substr($this->_recv_buf, 0, $aes_enc_part['plen']-4),
                 $this->_user_key, true);
            $handshake_my = substr($handshake_my, 0, 4);

            $part3 = substr($this->_recv_buf, 31 + $aes_enc_part['rlen'],  $aes_enc_part['plen'] - 31 - $aes_enc_part['rlen']);
            if( substr($part3, -4) !== $handshake_my) {
                echo "checksum error\n";
                return false;
            }
            $time_dif = $aes_enc_part['utc'] - time();
            if($time_dif < -self::$_max_time_dif || $time_dif > self::$_max_time_dif) {
                echo "wrong timestamp\n";
                return false;
            }
            $out_buf = substr($part3, 0, strlen($part3) - 4);
            $this->_recv_buf = substr($this->_recv_buf, $aes_enc_part['plen']);
            $this->_has_recv_header = true;
        }

        while( strlen($this->_recv_buf) > 4 ) {
            $hmac_key = $this->_user_key . pack('V', $this->_recv_id);
            $this_my = hash_hmac($this->_hashfunc, substr($this->_recv_buf, 0, 2), $hmac_key, true);
            $this_my = substr($this_my, 0, 2);
            if( substr($this->_recv_buf, 2, 2) !== $this_my) {
                if($this->_recv_id === 0) {
                    echo "over size\n";
                    return 'eeeeeeeeeeeeeee';
                } else {
                    echo "server_post_decrype data error\n";
                    return 'eeeeeeeeeeeeeee';
                }
            }
            $block_size = unpack('v1plen', substr($this->_recv_buf, 0, 2) );
            $block_size = $block_size['plen'];
            if($block_size >= 8192 || $block_size < 7) {
                $this->recv_buf = '';
                if($this->_recv_id === 0) {
                    echo "over size\n";
                    return 'eeeeeeeeeeeeeee';
                } else {
                    echo "server_post_decrype data length error\n";
                    return 'eeeeeeeeeeeeeee';
                }
            }
            if( strlen($this->_recv_buf) < $block_size) {
                break;
            }

            //echo $block_size . " <-- block_size\n";
            $block = substr($this->_recv_buf, 0, $block_size);
            $this->_recv_buf = substr($this->_recv_buf, $block_size);
            $this_my = hash_hmac($this->_hashfunc, substr($block, 0, $block_size-4), $hmac_key, true);
            $this_my = substr($this_my, 0, 4);
            if( substr($block, -4) !== $this_my) {
                $this->recv_buf = '';
                if($this->_recv_id === 0) {
                    echo "over size\n";
                    return 'eeeeeeeeeeeeeee';
                } else {
                    echo "server_post_decrype data checksum error\n";
                    return 'eeeeeeeeeeeeeee';
                }
            }

            $this->_recv_id = ($this->_recv_id + 1) & 0xFFFFFFFF;
            $pos = ord($block[4]);
            if($pos == 255) {
                $pos = (ord($block[5]) | ord($block[6])<<8);
            }
            $out_buf .= substr($block, $pos + 4, $block_size - 4 - $pos - 4);
        }

        return $out_buf;
    }

    public function ClientUdpPreEncrypt($plaindata)
    {
        return $plaindata;
    }

    public function ClientUdpPostDecrypt($plaindata)
    {
        return $plaindata;
    }

    public function ServerUdpPreEncrypt($plaindata)
    {
        return $plaindata;
    }

    public function ServerUdpPostDecrypt($plaindata)
    {
        return $plaindata;
    }

    protected function decrypt_no_bug($dat, $key)
    {
        $m = openssl_encrypt($dat , 'AES-128-ECB', $key, OPENSSL_RAW_DATA);
        $m = $dat . substr($m, 16, 32);
        return openssl_decrypt($m, 'AES-128-ECB', $key, OPENSSL_RAW_DATA);
    }

    protected function pack_data($buf)
    {
        $data = "\1" . $buf;
        $data_len = pack('v', strlen($data) + 8);
        $hmac_key = $this->_user_key . pack('V', $this->_pack_id);
        $this_my = hash_hmac($this->_hashfunc, $data_len, $hmac_key, true);
        $this_my = substr($this_my, 0, 2);
        $data = $data_len . $this_my . $data;
        $this_my = hash_hmac($this->_hashfunc, $data, $hmac_key, true);
        $this_my = substr($this_my, 0, 4);
        $data .= $this_my;
        $this->_pack_id = ($this->_pack_id + 1) & 0xFFFFFFFF;
        return $data;
    }

    protected function pack_auth_data($auth_data, $buf)
    {
        if( strlen($buf) == 0)
            return '';
        if( strlen($buf) > 400)
            $rnd_len = rand(0, 100);
        else
            $rnd_len = rand(0, 800);
        if(!self::$_padding_data) {
            $rnd_len = 0;
        }
        //---------------------part2-----------------------
        $data = $auth_data;
        $data_len = 7 + 4 + 16 + 4 + $rnd_len + strlen($buf) + 4;
        $data = $data . pack('v', $data_len) . pack('v', $rnd_len);
        $hmac_key = $this->_recv_iv . $this->_key;
        $uid = pack('V', $this->_user_id);
        $part2_enc_part_key = md5(base64_encode($this->_user_key) . $this->_protocol, true);
        $data = openssl_encrypt($data, 'AES-128-ECB', $part2_enc_part_key, OPENSSL_RAW_DATA);
        $data = $uid . substr($data, 0, 16);
        $handshake_my = hash_hmac($this->_hashfunc, $data, $hmac_key, true);
        $handshake_my = substr($handshake_my, 0, 4);
        $data .= $handshake_my;
        //---------------------part1-----------------------
        $check_head = openssl_random_pseudo_bytes(1);
        $handshake_my = hash_hmac($this->_hashfunc, $check_head, $hmac_key, true);
        $handshake_my = substr($handshake_my, 0, 6);
        $check_head .= $handshake_my;
        //---------------------part3-----------------------
        $data_rnd = openssl_random_pseudo_bytes($rnd_len);
        $pack = $check_head . $data . $data_rnd . $buf;
        $handshake_my = hash_hmac($this->_hashfunc, $pack, $this->_user_key, true);
        $handshake_my = substr($handshake_my, 0, 4);
        $pack .= $handshake_my;
        return $pack;
    }

    protected function auth_data()
    {
        $utc_time = intval(time());
        if(self::$_server_info['data']['connection_id'] > 0xff000000) {
            $this->_server_info['data']['local_client_id'] = '';
        }
        if(self::$_server_info['data']['local_client_id'] === '') {
            self::$_server_info['data']['local_client_id'] = openssl_random_pseudo_bytes(4);
            self::$_server_info['data']['connection_id'] = rand(0, 0xFFFFFF);
            echo "Reset client id: " . bin2hex(self::$_server_info['data']['local_client_id']) . "\n";
        }
        self::$_server_info['data']['connection_id']++;
        $auth = pack('V', $utc_time);
        $auth .= self::$_server_info['data']['local_client_id'];
        $auth .= pack('V', self::$_server_info['data']['connection_id']);
        return $auth;
    }

    protected function get_head_size($buf, $def_value)
    {
        if( strlen($buf) < 2)
            return $def_value;
        if($buf[0] === "\1")
            return 7;
        if($buf[0] === "\4")
            return 19;
        if($buf[0] === "\3")
            return 4 + ord($buf[1]);
        return $def_value;
    }
}
