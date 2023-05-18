<?php

namespace Config;

use CodeIgniter\Config\BaseConfig;

class APIJwt extends BaseConfig
{
    public $policyName = "default";

    /**
     * tokenSecret
     * Defines key to sign digitally the token JWT. 
     * To generate in hex2bin use: 
     *      php spark key:generate --show 
     * To generate in base64 use:
     *      php spark key:generate --show --prefix base64
     * 
     * You must store only the key, without algorithm prefix
     *
     * @var string
     *********************************************************** 
     *
     * hash
     * Defines hash used to sign JWT token. The signing algorithm.
     *      Supported algorithms are 'ES384','ES256', 'HS256', 'HS384',
     *      'HS512', 'RS256', 'RS384', and 'RS512'
     *
     * @var string
     *********************************************************** 
     * 
     * authTimeout
     * Defines timeout for token JWT, exp field into token JWT
     *      Set null to disable timeout
     *
     * @var int
     *********************************************************** 
     *
     * issuer
     * Issuer of the JWT
     *      Set null to ignore iss field from JWT token
     *
     * @var string
     *********************************************************** 
     * 
     * audience
     * Audience of the JWT
     *      Set null to ignore aud field from JWT token
     *
     * @var string
     *********************************************************** 
     * 
     * subject
     * Subject of the JWT
     *      Set null to ignore sub field from JWT token
     *
     * @var string
     *********************************************************** 
     * 
     * autoRenew
     * Renew automatically JWT token every request
     *
     * @var bool
     *********************************************************** 
     * 
     * oneTimeToken
     * JWT Token can be used only one time, toherwise is revoked
     *
     * @var bool
     *********************************************************** 
     */


public $default = [

    /**
     * To generate in hex2bin use: 
     *      php spark key:generate --show 
     * To generate in base64 use:
     *      php spark key:generate --show --prefix base64
     * 
     */
    'tokenSecret'  => 'b952674c72eff0e5e482b7525cde57a1fcdddc486a89658fd8985169cda341e9', //hex2bin.
    'hash'         => "HS256",
    'authTimeout'  => 30 * HOUR,
    'issuer'       => "daw-company",
    'audience'     => "daw-company.user-db",
    'subject'      => "secure.jwt.v1.daw",
    'autoRenew'    => true,
    'oneTimeToken' => true,
    'renewTokenField' => 'token',
    'includePolicy' => true,
];

public $test = [
    'tokenSecret'  => 'e2980ce7a6b877cff666ae064da0bb88be6216b7a9ee562a8753ad22bf5c048c', //hex2bin.
    'hash'         => "HS256",
    'authTimeout'  => 1 * HOUR,
    'issuer'       => "test-company",
    'audience'     => "test-company.user-db",
    'subject'      => "secure.jwt.v1.test",
    'autoRenew'    => true,
    'oneTimeToken' => true,
    'renewTokenField' => 'token',
    'includePolicy' => true,
];



    public function __construct($policy = null)
    {
        parent::__construct();

        if ($policy != null)
            $this->policyName = $policy;
    }

    /**
     * Returns deafult configuration or configuration group 
     * 
     * @param  mixed $groupName Config groupname to get
     * @return object
     */
    public function config($policy = null)
    {
        if ($policy == null) $policy = $this->policyName;

        $props = get_object_vars($this);

        if (isset($props[$policy]) && is_array($props[$policy])) {
            $props[$policy]["policy"] = $policy;
            return (object) $props[$policy];
        } else {
            $props[$this->policyName]["policy"] = $this->policyName;
            return (object) $props[$this->policyName];
        }
    }
}
