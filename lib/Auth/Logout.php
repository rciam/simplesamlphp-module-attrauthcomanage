<?php

namespace SimpleSAML\Module\attrauthcomanage\Auth;

use SimpleSAML\Utils\HTTP;
use SimpleSAML\Module;
use SimpleSAML\Idp;

/**
 *
 * @package SimpleSAMLphp
 */
class Logout {
    public static function postLogout(IdP $idp, array $state) {
        $url = Module::getModuleURL('attrauthcomanage/logout.ctrl.php');
        HTTP::redirectTrustedURL($url);
    }
}
