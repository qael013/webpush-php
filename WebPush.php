<?php
function base64_to_urlsafe(string $plain){
	return sodium_bin2base64($plain, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
}
function base64_from_urlsafe(string $encoded){
	return sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
}

class WebPush {
    private const string VAPID_SIGN_ALGORITHM = 'ES256';
    private const int VAPID_SIGN_NUM_LEN = 32;
    private const int VAPID_MIN_EXP = 300;
    private const string EC_CURVE = 'prime256v1';
    private const int SALT_LEN = 16;
    private const string HASH_ALGORITHM = 'sha256';
    private const string CRYPTO_ALGORITHM = 'aes-128-gcm';
    private const string CRYPTO_ALGORITHM_NODASH = 'aes128gcm';

    private OpenSSLAsymmetricKey $vapid_key;
    protected string $vapid_public;
    private string $vapid_aud;
    private int $vapid_exp_slot;
    private string $vapid_mail;
    private string $last_jwt_file;
    private string $last_jwt;
    private int $last_jwt_exp;
    private string $endpoint;
    private OpenSSLAsymmetricKey $ua_key;
    private string $ua_public;
    private string $auth_secret;

    public function __construct(
        #[\SensitiveParameter] string $endpoint,
        #[\SensitiveParameter] string $ua_public,
        #[\SensitiveParameter] string $auth_secret,
        string $vapid_file = 'vapid.json'
    ){
        $vapid_file_content = file_get_contents(__DIR__ . "/{$vapid_file}");
        $raw_vapid = json_decode($vapid_file_content, false);
        $this->vapid_key = openssl_pkey_new([
            'ec' => [
                'curve_name' => static::EC_CURVE,
                'd' => base64_from_urlsafe($raw_vapid->key),
            ]
        ]);
        if($vapid_file_content === false || $raw_vapid === null || $this->vapid_key === false){
            throw new Error('Impossible to create WebPush object: cannot load VAPID key');
        }
        $vapid_key_details = openssl_pkey_get_details($this->vapid_key)['ec'];
        $this->vapid_public = base64_to_urlsafe("\x04{$vapid_key_details['x']}{$vapid_key_details['y']}");
        $vapid_aud = parse_url($endpoint);
        $this->vapid_aud = "{$vapid_aud['scheme']}://{$vapid_aud['host']}";
        $this->vapid_exp_slot = min($raw_vapid->exp_slot, 86400 - static::VAPID_MIN_EXP);
        $this->vapid_mail = $raw_vapid->mail;

        $this->last_jwt_file = 'last_jwt_' . base64_to_urlsafe($this->vapid_aud) . '.json';
        try{
            $last_jwt_file_content = file_get_contents(__DIR__ . "/{$this->last_jwt_file}");
        }catch(e){}
        $raw_last_jwt = json_decode($last_jwt_file_content, false);
        if($last_jwt_file_content !== false && $raw_last_jwt !== null){
            $this->last_jwt = $raw_last_jwt->jwt;
            $this->last_jwt_exp = $raw_last_jwt->exp;
        }else{
            $this->last_jwt = '';
            $this->last_jwt_exp = 0;
        }

        $this->endpoint = $endpoint;

        $ua_public = base64_from_urlsafe($ua_public);
        $this->ua_key = openssl_pkey_new([
            'ec' => [
                'curve_name' => static::EC_CURVE,
                'x' => substr($ua_public, 1, 32),
                'y' => substr($ua_public, 33),
            ]
        ]);
        if(substr($ua_public, 0, 1) !== "\x04" || strlen($ua_public) !== 65 || $this->ua_key === false){
            throw new Error('Impossible to create WebPush object: invalid user agent public key');
        }
        $this->ua_public = $ua_public;

        $this->auth_secret = base64_from_urlsafe($auth_secret);
    }

    public function send(
        string $message,
        string $content_type = 'text/plain',
        int $ttl = 15,
        string $urgency = 'normal',
        string $topic = ''
    ) : bool {
        $jwt = $this->vapid_jwt();
        if($jwt === ''){
            throw new Error('Couldn\'t build JWT token');
        }

        $cipher = $this->encrypt($message);

        $options = [
            CURLOPT_POST => true,
            CURLOPT_URL => $this->endpoint,
            CURLOPT_POSTFIELDS => $cipher,
            CURLOPT_HTTPHEADER => [
                'Prefer: respond-async',
                "TTL: {$ttl}",
                "Content-Type: {$content_type}",
                'Content-Encoding: ' . static::CRYPTO_ALGORITHM_NODASH,
                'Content-Length: ' . strlen($cipher),
                "Urgency: {$urgency}",
                "Authorization: vapid t={$jwt},k={$this->vapid_key()}",
            ],
            CURLOPT_RETURNTRANSFER => false,
        ];
        if($topic !== ''){
            $options[CURLOPT_HTTPHEADER][] = "Topic: {$topic}";
        }

        $request = curl_init();
        if(curl_setopt_array(
            handle : $request,
            options : $options
        ) === false){
            throw new Warning('Couldn\'t set options for cURL WebPush request');
            return false;
        }

        curl_exec($request);

        return curl_getinfo($request, CURLINFO_HTTP_CODE) === 201;
    }

    private function encrypt($message) : string {
        $as_key = openssl_pkey_new([
            'ec' => [
                'curve_name' => static::EC_CURVE,
            ]
        ]);
        $salt = random_bytes(static::SALT_LEN);

        return $this->nonrandom_encrypt($message, $as_key, $salt);
    }

    protected function nonrandom_encrypt(
        string $message,
        #[\SensitiveParameter] OpenSSLAsymmetricKey $as_key,
        #[\SensitiveParameter] string $salt,
    ) : string {
        $as_details = openssl_pkey_get_details($as_key)['ec'];
        $as_public = "\x04{$as_details['x']}{$as_details['y']}";

        $shared_ecdh_secret = openssl_pkey_derive($this->ua_key, $as_key);
        $prk_key = hash_hmac(static::HASH_ALGORITHM, $shared_ecdh_secret, $this->auth_secret, true);

        $ikm = hash_hmac(static::HASH_ALGORITHM, "WebPush: info\x00{$this->ua_public}{$as_public}\x01", $prk_key, true);

        $prk = hash_hmac(static::HASH_ALGORITHM, $ikm, $salt, true);

        $cek = substr(hash_hmac(static::HASH_ALGORITHM, 'Content-Encoding: ' . static::CRYPTO_ALGORITHM_NODASH . "\x00\x01", $prk, true), 0, openssl_cipher_key_length(static::CRYPTO_ALGORITHM));
        $nonce = substr(hash_hmac(static::HASH_ALGORITHM, "Content-Encoding: nonce\x00\x01", $prk, true), 0, openssl_cipher_iv_length(static::CRYPTO_ALGORITHM));
    
        $header = "{$salt}\x00\x00\x10\x00\x41{$as_public}";
        $cypher = openssl_encrypt("{$message}\x02", static::CRYPTO_ALGORITHM, $cek, OPENSSL_RAW_DATA, $nonce, $tag) . $tag;

        return $header . $cypher;
    }

    public function vapid_key() : string {
        return $this->vapid_public;
    }

    private function vapid_jwt() : string {
        $exp_time = time() + static::VAPID_MIN_EXP + $this->vapid_exp_slot;
        $exp_time -= $exp_time % $this->vapid_exp_slot;

        if($exp_time === $this->last_jwt_exp){
            return $this->last_jwt;
        }

        return $this->static_vapid_jwt($exp_time);
    }

    protected function static_vapid_jwt(int $exp_time) : string {
        $jwt_header = '{"typ":"JWT","alg":"' . static::VAPID_SIGN_ALGORITHM . '"}';

        $jwt_body = [
            'aud' => $this->vapid_aud,
            'exp' => $exp_time,
            'sub' => "mailto:{$this->vapid_mail}",
        ];

        $jwt = base64_to_urlsafe($jwt_header) . '.' . base64_to_urlsafe(json_encode($jwt_body, JSON_UNESCAPED_SLASHES));

        if(openssl_sign($jwt, $signature, $this->vapid_key, static::HASH_ALGORITHM) === false){
            return '';
        }

        $rlen = ord($signature[3]);
        $r = substr($signature, 4, $rlen);
        $slen = ord($signature[5 + $rlen]);
        $s = substr($signature, 6 + $rlen, $slen);
        if($rlen > static::VAPID_SIGN_NUM_LEN){
            $r = substr($r, 1);
        }else if($rlen < static::VAPID_SIGN_NUM_LEN){
            $r = str_pad($r, static::VAPID_SIGN_NUM_LEN, "\0", STR_PAD_LEFT);
        }
        if($slen > static::VAPID_SIGN_NUM_LEN){
            $s = substr($s, 1);
        }else if($slen < static::VAPID_SIGN_NUM_LEN){
            $s = str_pad($s, static::VAPID_SIGN_NUM_LEN, "\0", STR_PAD_LEFT);
        }

        $jwt .= '.' . base64_to_urlsafe("{$r}{$s}");
        file_put_contents(__DIR__ . "/{$this->last_jwt_file}", json_encode([
            'jwt' => $jwt,
            'exp' => $exp_time,
        ]));

        return $jwt;
    }

    public function __debugInfo() : array {
        return [];
    }
}
?>