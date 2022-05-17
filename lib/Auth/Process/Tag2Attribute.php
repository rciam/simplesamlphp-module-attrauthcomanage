<?php

namespace SimpleSAML\Module\attrauthcomanage\Auth\Process;

use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Utils\Config;

class Tag2Attribute extends \SimpleSAML\Auth\ProcessingFilter
{
    private $targetAttribute = 'urn:oid:1.3.6.1.4.1.25178.1.2.10'; //'schacHomeOrganizationType';

    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (array_key_exists('targetAttribute', $config)) {
            if (!is_string($config['targetAttribute'])) {
                Logger::error(
                    "[tag2attribute] Configuration error: 'targetAttribute' is not a string"
                );
                throw new \Exception(
                    "tag2attribute configuration error: 'targetAttribute' is not a string"
                );
            }
        }
    }

    public function process(&$state)
    {
        try {
            assert('is_array($state)');
            Logger::debug("[tag2attribute] process");
            $idpTags = $this->getIdPTags($this->getIdPMetadata($state));
            if (!empty($idpTags)) {
                $state['Attributes'][$this->targetAttribute] = $idpTags;
                Logger::debug("[tag2attribute] process: targetAttribute > " . var_export($state['Attributes'][$this->targetAttribute], true));
            }
        } catch (Error\Error $e) {
            $e->show();
        }
    }

    private function getIdPMetadata($state)
    {
        // If the module is active on a bridge,
        // $request['saml:sp:IdP'] will contain an entry id for the remote IdP.
        if (!empty($state['saml:sp:IdP'])) {
            $idpEntityId = $state['saml:sp:IdP'];
            return MetaDataStorageHandler::getMetadataHandler()->getMetaData($idpEntityId, 'saml20-idp-remote');
        } else {
            return $state['Source'];
        }
    }

    private function getIdPTags($idpMetadata)
    {
        if (!empty($idpMetadata['tags'])) {
            return $idpMetadata['tags'];
        }
        return [];
    }
}
