<?php
/**
 * This Class is a Helper class for COmanageDbClient class
 * It is used to fetch COPerson's active SSH keys
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 * @author Nick Evangelou <nikosev@grnet.gr>
 * @author Ioannis Igoumenos <ioigoume@grnet.gr>
 */

namespace SimpleSAML\Module\attrauthcomanage\Attributes;

use PDO;
use SimpleSAML\Error;
use SimpleSAML\Logger;

class SshPublicKey
{

    public static $SSH_PUBLIC_KEY_TYPE = [
        'DSA' => 'ssh-dss',
        'ECDSA' => 'ecdsa-sha2-nistp256',
        'ECDSA384' => 'ecdsa-sha2-nistp384',
        'ECDSA521' => 'ecdsa-sha2-nistp521',
        'ED25519' => 'ssh-ed25519',
        'RSA' => 'ssh-rsa',
        'RSA1' => 'ssh-rsa1',
    ];

    /**
     * Query the SSH table and fetch all SSH keys related to the CO Person
     *
     * @param integer $personId     Id of the CO Person
     *
     * @return array                List of SSH keys. Each entry contains: [type, skey, comment]
     *
     * [
     *   {
     *     "type": "RSA",
     *     "skey": "AAAAB3NzaC1y...............AAAAAAAAAA",
     *     "comment": "my super secure ssh key"
     *   }
     * ]
     *
     */
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

        Logger::debug("[attrauthcomanage] getSshPublicKeys: personId="
            . var_export($personId, true));

        $result = [];
        $db = Database::getInstance();
        $queryParams = [
            'coPersonId' => [$personId, PDO::PARAM_INT],
        ];
        $stmt = $db->read($sshKeysQuery, $queryParams);
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $result[] = $row;
            }
            Logger::debug("[attrauthcomanage] getSshPublicKeys: result="
                . var_export($result, true));
            return $result;
        } else {
            throw new Exception('Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true));
        }

        return $result;
    }

    // todo: This is redundant. Remove it
    public static function getSshPublicKeyType($key)
    {
        return self::$SSH_PUBLIC_KEY_TYPE[$key];
    }
}