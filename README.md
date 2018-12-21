# shadowsocks-php
A php port of [shadowsocks](https://github.com/shadowsocks/shadowsocks) based on [Workerman](https://github.com/walkor/Workerman), compatible with OutLine


## Dependencies
* openssl
* sodium (optional)
* gmp (optional)

## Configuration

| Parameters | Type | Description |
| :------------- | :-------------: | :------------- |
| \$MODE           |  string  | Select server or local mode |
| \$UDP_ENABLE     |  bool    | Enable UDP relay     |
| \$SERVER         |  string  | Host name or IP address of your remote server  |
| \$PORT           | int      | Port number of server  |
| \$METHOD         | string   | Encrypt method |
| \$PASSWORD       | string   | Password of your remote server |
| \$PROTOCOL       |  string  | Name of your protocol plugin |
| \$PROTOCOL_PARAM | array    | Parameters of your protocol plugin |
| \$LOCAL_PORT     | int      | Port number of your local server |
| \$PROCESS_COUNT  | int      | Number of processes |

    Applications/Shadowsocks/config.php

### Supported Ciphers
#### openssl ciphers
* `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `bf-cfb`
* `camellia-128-cfb`, `camellia-192-cfb`, `camellia-256-cfb`, `cast5-cfb`
* `des-cfb`, `idea-cfb`, `rc2-cfb`, `seed-cfb`
* `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`
* `chacha20`, `chacha20-ietf`
* `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`
#### sodium ciphers
* `chacha20-poly1305`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`
#### native ciphers
* `rc4`, `rc4-md5`, `rc4-md5-6`
* `none` (No encryption, just for debugging)


### Supported Protocol
* `origin`
* `auth_aes128_md5`, `auth_aes128_sha1` (experimental)


## Start

    $ php start.php start -d


## Stop

    $ php start.php stop


## Status

    $ php start.php status


## Other links
https://github.com/walkor/php-socks5  
https://github.com/walkor/php-http-proxy
