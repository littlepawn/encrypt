<?php

class Rsa {
    private static $PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCeXviS+4ydV/bdwjRvyp+omr5EsGHWtgE2s3466J6sch/1r7wc
2qGgbopz/V9cQdOy5eRRXy2/2PLP5/hEwBm0sFfRSrsQP/kOa0cBqzQHqTHonx5h
xfOXpm+osHBmafooKp4Vc+JvT0AjNm8p2cXNE4ZSbOx5dKKXlUzwmdiuYQIDAQAB
AoGAHsMf0Z0fESkXALhKazSWkq+MKdeBCa3Myo1PBa5Ns/1vC9AY4BnvrzQJnMIo
lckLkAJruQqd3lgLwiqy5NfTpiEjTpOBDyK99ohc6ACrvllZNL99WVZC7ul8k9Kj
cHTjWgDXmHyiDKkDyHFL0mLcO4DsbnXJX3DrS6OKqPTj0YkCQQDOemepyawMXeza
LKa+K0Ko4zYfvd9eySGzJLsoV6/8YTq/Cn1QkMyPjHNPW0gIWTtj26PjL2Ab8Hr7
HRNF9t1LAkEAxFrS/RgcQIjixuNoSZXhfsSUer/vSUbpsefCZDHok2hxx7qAHz7y
mrDNXLc4wofAHfN+B0S8eQSNKT5LIx6zgwJBAKIszE00pNjV0RoQJiuJ6QKj67gE
t3RIgBqoCASI0yZk6/Jvd7wW70T0qQE0jiBYjehB9LiVVmS7fqzLyn6Shn8CQDbL
pc+tl8zGpoqcUbEfW5NV5p2uzGclm/fi1lPBvcbNQdtcB38wwOE8b8Ls+rEG0y1I
kyYSH4qiI4ab9LnzSmMCQG8F1zhfSQZdNzCCm9PhwSAXQbFiPsPYSEgH77fFgh8h
Iiho4VP20zAj9GVN2cJyMcGhFjy/kodHv56XTxs+q6o=
-----END RSA PRIVATE KEY-----';
    private static $PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeXviS+4ydV/bdwjRvyp+omr5E
sGHWtgE2s3466J6sch/1r7wc2qGgbopz/V9cQdOy5eRRXy2/2PLP5/hEwBm0sFfR
SrsQP/kOa0cBqzQHqTHonx5hxfOXpm+osHBmafooKp4Vc+JvT0AjNm8p2cXNE4ZS
bOx5dKKXlUzwmdiuYQIDAQAB
-----END PUBLIC KEY-----';
 
    /**     
     * 获取私钥     
     * @return bool|resource     
     */    
    private static function getPrivateKey() 
    {        
        $privKey = self::$PRIVATE_KEY;        
        return openssl_pkey_get_private($privKey);    
    }    

    /**     
     * 获取公钥     
     * @return bool|resource     
     */    
    private static function getPublicKey()
    {        
        $publicKey = self::$PUBLIC_KEY;        
        return openssl_pkey_get_public($publicKey);    
    }    

    /**     
     * 私钥加密     
     * @param string $data     
     * @return null|string     
     */    
    public static function privEncrypt($data = '')    
    {        
        if (!is_string($data)) {            
            return null;       
        }
        return openssl_private_encrypt($data,$encrypted,self::getPrivateKey()) ? base64_encode($encrypted) : null;
    }

    /**
     * 私钥加密（字符长度不限制）
     * @param string $data
     * @return null|string
     */
    public static function privateKeyEncrypt($data=''){
        $split = str_split($data, 117);  // 1024 bit && OPENSSL_PKCS1_PADDING  不大于117即可
        $crypto = '';
        foreach ($split as $chunk) {
            $isOkay = openssl_private_encrypt($chunk, $encryptData, self::getPrivateKey());
            if(!$isOkay){
                return false;
            }
            $crypto .= base64_encode($encryptData);
        }
        return $crypto;
    }

    /**     
     * 公钥加密     
     * @param string $data     
     * @return null|string     
     */    
    public static function publicEncrypt($data = '')   
    {        
        if (!is_string($data)) {            
            return null;        
        }        
        return openssl_public_encrypt($data,$encrypted,self::getPublicKey()) ? base64_encode($encrypted) : null;    
    }

    /**
     * 公钥加密（字符长度不限制）
     * @param string $data
     * @return null|string
     */
    public static function publicKeyEncrypt($data=''){
        $split = str_split($data, 117);  // 1024 bit && OPENSSL_PKCS1_PADDING  不大于117即可
        $crypto = '';
        foreach ($split as $chunk) {
            $isOkay = openssl_public_encrypt($chunk, $encryptData, self::getPublicKey());
            if(!$isOkay){
                return false;
            }
            $crypto .= base64_encode($encryptData);
        }
        return $crypto;
    }

    /**     
     * 私钥解密     
     * @param string $encrypted     
     * @return null     
     */    
    public static function privDecrypt($encrypted = '')    
    {        
        if (!is_string($encrypted)) {            
            return null;        
        }        
        return (openssl_private_decrypt(base64_decode($encrypted), $decrypted, self::getPrivateKey())) ? $decrypted : null;    
    }

    /**
     * 私钥解密（字符长度不限制）
     * @param string $encrypted
     * @return null
     */
    public static function privateKeyDecrypt($encrypted = ''){
        if (!is_string($encrypted)) {
            return null;
        }
        $split = str_split($encrypted, 172);  // 1024 bit  固定172
        $crypto = '';
        foreach ($split as $chunk) {
            $isOkay = openssl_private_decrypt(base64_decode($chunk), $decryptData, self::getPrivateKey());  // base64在这里使用，因为172字节是一组，是encode来的
            if(!$isOkay){
                return false;
            }
            $crypto .= $decryptData;
        }
        return $crypto;
    }

    /**     
     * 公钥解密     
     * @param string $encrypted     
     * @return null     
     */    
    public static function publicDecrypt($encrypted = '')    
    {        
        if (!is_string($encrypted)) {            
            return null;        
        }        
        return (openssl_public_decrypt(base64_decode($encrypted), $decrypted, self::getPublicKey())) ? $decrypted : null;
    }

    /**
     * 公钥解密（字符长度不限制）
     * @param string $encrypted
     * @return null
     */
    public static function publicKeyDecrypt($encrypted = ''){
        if (!is_string($encrypted)) {
            return null;
        }
        $split = str_split($encrypted, 172);  // 1024 bit  固定172
        $crypto = '';
        foreach ($split as $chunk) {
            $isOkay = openssl_public_decrypt(base64_decode($chunk), $decryptData, self::getPublicKey());  // base64在这里使用，因为172字节是一组，是encode来的
            if(!$isOkay){
                return false;
            }
            $crypto .= $decryptData;
        }
        return $crypto;
    }
}
