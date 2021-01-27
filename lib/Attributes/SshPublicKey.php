<?php

/**
 * Class sspmod_attrauthcomanage_Attributes_SshPublicKey
 */
class sspmod_attrauthcomanage_Attributes_SshPublicKey
{
    /**
     * @var string
     */
    protected $sshKeysQuery = 'SELECT'
    . " DISTINCT ssh.type, ssh.skey, ssh.comment"
    . " FROM cm_ssh_keys AS ssh"
    . " INNER JOIN cm_co_people AS person"
    . " ON person.id = ssh.co_person_id"
    . " WHERE person.id = :coPersonId"
    . " AND NOT person.deleted"
    . " AND person.co_person_id IS NULL"
    . " AND ssh.ssh_key_id IS NULL"
    . " AND NOT ssh.deleted;";


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
        SimpleSAML_Logger::debug("[attrauthcomanage] getSshPublicKeys: personId="
            . var_export($personId, true));

        $result = array();
        $db = SimpleSAML\Database::getInstance();
        $queryParams = array(
            'coPersonId' => array($personId, PDO::PARAM_INT),
        );
        $stmt = $db->read($this->sshKeysQuery, $queryParams);
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

    /**
     * @param array $sshKeyParts
     * Import array structure
     * [
     *   {
     *     "type": "RSA",
     *     "skey": "AAAAB3NzaC1y...............AAAAAAAAAA",
     *     "comment": "my super secure ssh key"
     *   }
     * ]
     *
     * @return string
     */
    public function formatSshKey($sshKeyParts) {
        $sshKey = "";
        if(!empty($sshKeyParts['skey']) && !empty($sshKeyParts['type'])) {
            $sshKey = sspmod_attrauthcomanage_Enums_SshKeyTypeEnum::getKeyType($sshKeyParts['type'])
                . ' '
                . $sshKeyParts['skey']
                . (!empty($sshKeyParts['comment']) ? ' ' . $sshKeyParts['comment'] : '');
        }
        return $sshKey;
    }

}
