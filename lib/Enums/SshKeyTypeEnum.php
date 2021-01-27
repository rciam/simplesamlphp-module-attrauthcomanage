<?php
/**
 * Class sspmod_attrauthcomanage_Enums_StatusEnum
 *
 * SSH key types abbraviation
 *
 * todo: Change const to public const for php version >=7.1
 */
class sspmod_attrauthcomanage_Enums_SshKeyTypeEnum extends sspmod_attrauthcomanage_Enums_EnumAbstract
{
    const DSA       = 'ssh-dss';
    const ECDSA     = 'ecdsa-sha2-nistp256';
    const ECDSA384  = 'ecdsa-sha2-nistp384';
    const ECDSA521  = 'ecdsa-sha2-nistp521';
    const ED25519   = 'ssh-ed25519';
    const RSA       = 'ssh-rsa';
    const RSA1      = 'ssh-rsa1';
}
