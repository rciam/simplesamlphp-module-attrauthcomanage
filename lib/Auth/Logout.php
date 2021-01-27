<?php

/**
 *
 * @package SimpleSAMLphp
 */
class sspmod_attrauthcomanage_Auth_Logout {

    public static function postLogout(SimpleSAML_IdP $idp, array $state) {
        $url = SimpleSAML_Module::getModuleURL('attrauthcomanage/logout.ctrl.php');
        \SimpleSAML\Utils\HTTP::redirectTrustedURL($url);
    }

}