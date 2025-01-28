<?php
/*
* File: ImapProtocol.php
* Category: Protocol
* Author: M.Goldenbaum
* Created: 16.09.20 18:27
* Updated: -
*
* Description:
*  -
*/

namespace Webklex\PHPIMAP\Connection;

/**
 * Class SslOptions
 *
 * @package Webklex\PHPIMAP\Connection\Protocols
 */
class SslOptions
{
    /* The complete list of SSL context options @see https://www.php.net/manual/en/context.ssl.php for details on each option */
    public const PEER_NAME               = 'peer_name';
    public const VERIFY_PEER             = 'verify_peer';
    public const VERIFY_PEER_NAME        = 'verify_peer_name';
    public const ALLOW_SELF_SIGNED       = 'allow_self_signed';
    public const CAFILE                  = 'cafile';
    public const CAPATH                  = 'capath';
    public const LOCAL_CERT              = 'local_cert';
    public const LOCAL_PK                = 'local_pk';
    public const PASSPHRASE              = 'passphrase';
    public const VERIFY_DEPTH            = 'verify_depth';
    public const CIPHERS                 = 'ciphers';
    public const CAPTURE_PEER_CERT       = 'capture_peer_cert';
    public const CAPTURE_PEER_CERT_CHAIN = 'capture_peer_cert_chain';
    public const SNI_ENABLED             = 'SNI_enabled';
    public const DISABLE_COMPRESSION     = 'disable_compression';
    public const PEER_FINGERPRINT        = 'peer_fingerprint';
    /* Only available on PHP >= 7.2.0 */
    public const SECURITY_LEVEL = 'security_level';

    /* Authorized types for the options */
    protected const TYPE_ARRAY           = 'array';
    protected const TYPE_BOOL            = 'bool';
    protected const TYPE_INT             = 'int';
    protected const TYPE_STRING          = 'string';
    protected const TYPE_STRING_OR_ARRAY = 'string|array';

    /**
     * Checks if an SSL context option with the given name exists
     *
     * @param string $name
     *
     * @return bool
     */
    public static function optionExists(string $name): bool
    {
        return array_key_exists($name, self::getOptionsList());
    }

    /**
     * Checks if an SSL context option with the given name exists and if the given value is of the expected type
     *
     * @param string $name
     * @param mixed  $value
     *
     * @return bool
     */
    public static function isOptionValid(string $name, mixed $value): bool
    {
        return self::optionExists($name) && self::checkValueType($value, self::getOptionsList()[$name]);
    }

    /**
     * @return string[]
     */
    protected static function getOptionsList(): array
    {
        $options = [
            self::PEER_NAME               => self::TYPE_STRING,
            self::VERIFY_PEER             => self::TYPE_BOOL,
            self::VERIFY_PEER_NAME        => self::TYPE_BOOL,
            self::ALLOW_SELF_SIGNED       => self::TYPE_BOOL,
            self::CAFILE                  => self::TYPE_STRING,
            self::CAPATH                  => self::TYPE_STRING,
            self::LOCAL_CERT              => self::TYPE_STRING,
            self::LOCAL_PK                => self::TYPE_STRING,
            self::PASSPHRASE              => self::TYPE_STRING,
            self::VERIFY_DEPTH            => self::TYPE_INT,
            self::CIPHERS                 => self::TYPE_STRING,
            self::CAPTURE_PEER_CERT       => self::TYPE_BOOL,
            self::CAPTURE_PEER_CERT_CHAIN => self::TYPE_BOOL,
            self::SNI_ENABLED             => self::TYPE_BOOL,
            self::DISABLE_COMPRESSION     => self::TYPE_BOOL,
            self::PEER_FINGERPRINT        => self::TYPE_STRING_OR_ARRAY,
        ];

        if (PHP_VERSION_ID >= 70200) {
            $options[self::SECURITY_LEVEL] = self::TYPE_INT;
        }

        return $options;
    }

    /**
     * @param mixed  $value
     * @param string $type
     *
     * @return bool
     */
    protected static function checkValueType(mixed $value, string $type): bool
    {
        return match ($type) {
            self::TYPE_ARRAY            => is_array($value),
            self::TYPE_BOOL             => is_bool($value),
            self::TYPE_INT              => is_int($value),
            self::TYPE_STRING           => is_string($value),
            self::TYPE_STRING_OR_ARRAY  => is_array($value) || is_string($value),
            default => false,
        };
    }
}