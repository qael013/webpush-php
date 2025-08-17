<?php
require_once 'WebPush.php';

class WebPush_Test extends WebPush {
    public static function test(){
        echo "----- WebPush TEST START -----\n";
        echo 'WebPush Encrypt Test: ' . (static::encrypt_test() ? 'PASSED' : 'FAILED') . "\n";
        echo 'WebPush VAPID Test: ' . (static::vapid_test() ? 'PASSED' : 'FAILED') . "\n";
        echo "----- WebPush TEST END -----\n";
    }

    public static function encrypt_test() : bool {
        $webpush = new WebPush(
            endpoint : '',
            ua_public : 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
            auth_secret : 'BTBZMqHH6r4Tts7J_aSIgg',
        );

        $as_key = openssl_pkey_new([
            'ec' => [
                'curve_name' => 'prime256v1',
                'd' => Base64::from_urlsafe('yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw'),
            ]
        ]);

        $cipher = $webpush->nonrandom_encrypt(
            message : 'When I grow up, I want to be a watermelon',
            as_key : $as_key,
            salt : Base64::from_urlsafe('DGv6ra1nlYgDCS1FRnbzlw'),
        );

        $expected_result = Base64::from_urlsafe('DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN');

        return $cipher === $expected_result;
    }

    public static function vapid_test() : bool {
        $webpush = new WebPush(
            endpoint : 'https://push.example.net/p/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV',
            ua_public : 'BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs',
            auth_secret : '',
            vapid_file : 'vapid_test.json'
        );

        $jwt = $webpush->static_vapid_jwt(1453523768);

        $jwt_array = explode('.', $jwt);
        if(count($jwt_array) !== 3){
            return false;
        }

        list($jwt_header, $jwt_body, $jwt_signature) = $jwt_array;

        $jwt_block = "{$jwt_header}.{$jwt_body}";
        $expected_block = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0';
        if($jwt_block !== $expected_block){
            return false;
        }

        $jwt_signature = Base64::from_urlsafe($jwt_signature);
        $r = substr($jwt_signature, 0, 32);
        while($r[0] === "\0"){
            $r = substr($r, 1);
        }
        if(($r & "\x80") === "\x80"){
            $r = "\x00{$r}";
        }
        $rlen = strlen($r);

        $s = substr($jwt_signature, 32);
        while($s[0] === "\0"){
            $s = substr($s, 1);
        }
        if(($s & "\x80") === "\x80"){
            $s = "\x00{$s}";
        }
        $slen = strlen($s);

        $asn1_signature = "\x30" . chr(4 + $rlen + $slen) . "\x02" . chr($rlen) . "{$r}\x02" . chr($slen) . $s;

        $vapid_public_key = openssl_pkey_new([
            'ec' => [
                'curve_name' => 'prime256v1',
                'x' => substr($webpush->vapid_public, 1, 32),
                'y' => substr($webpush->vapid_public, 33),
            ]
        ]);

        return openssl_verify($jwt_block, $asn1_signature, $vapid_public_key, 'sha256') === 1;
    }
}

WebPush_Test::test();
?>