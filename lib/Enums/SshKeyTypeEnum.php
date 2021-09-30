<?php

namespace SimpleSAML\Module\attrauthcomanage\Enums;

/**
 * Interface SshKeyTypeEnum
 *
 * SSH key types abbreviation
 */
interface SshKeyTypeEnum
{
    public const DSA       = 'ssh-dss';
    public const ECDSA     = 'ecdsa-sha2-nistp256';
    public const ECDSA384  = 'ecdsa-sha2-nistp384';
    public const ECDSA521  = 'ecdsa-sha2-nistp521';
    public const ED25519   = 'ssh-ed25519';
    public const RSA       = 'ssh-rsa';
    public const RSA1      = 'ssh-rsa1';
}
