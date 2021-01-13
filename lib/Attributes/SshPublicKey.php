<?php

class sspmod_attrauthcomanage_Attributes_SshPublicKey
{

    public static $SSH_PUBLIC_KEY_TYPE = array(
        'DSA' => 'ssh-dss',
        'ECDSA' => 'ecdsa-sha2-nistp256',
        'ECDSA384' => 'ecdsa-sha2-nistp384',
        'ECDSA521' => 'ecdsa-sha2-nistp521',
        'ED25519' => 'ssh-ed25519',
        'RSA' => 'ssh-rsa',
        'RSA1' => 'ssh-rsa1',
    );

    public function getSshPublicKeys($personId)
    {
        $sshKeysQuery = 'SELECT'
        . ' DISTINCT ssh.type, ssh.skey, ssh.comment'
        . ' FROM cm_ssh_keys AS ssh'
        . ' INNER JOIN cm_co_people AS person'
        . ' ON person.id = ssh.co_person_id'
        . ' WHERE person.id = :coPersonId'
        . ' AND NOT person.deleted'
        . ' AND person.co_person_id IS NULL'
        . ' AND ssh.ssh_key_id IS NULL'
        . ' AND NOT ssh.deleted';

        SimpleSAML_Logger::debug("[attrauthcomanage] getSshPublicKeys: personId="
            . var_export($personId, true));

        $result = array();
        $db = SimpleSAML\Database::getInstance();
        $queryParams = array(
            'coPersonId' => array($personId, PDO::PARAM_INT),
        );
        $stmt = $db->read($sshKeysQuery, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            SimpleSAML_Logger::debug("[attrauthcomanage] getSshPublicKeys: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true));
        }

        return $result;
    }

    public static function getSshPublicKeyType($key)
    {
        return self::$SSH_PUBLIC_KEY_TYPE[$key];
    }
}
