<?php
if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SimpleSAML_Error_BadRequest(
        'Missing required StateId query parameter.'
    );
}
$id = $_REQUEST['StateId'];
/* Restore state */
$state = SimpleSAML_Auth_State::loadState($id, 'attrauthcomanage_noty_state');


// XXX Get Noty Configuration from state
if (!array_key_exists('noty', $state)) {
    throw new SimpleSAML_Error_Assertion(
        'Missing required noty state parameter.'
    );
}
SimpleSAML_Logger::debug("noty REQUEST => ". var_export($_REQUEST, true));

// XXX YES/CONFIRM Action SECTION
if (array_key_exists('yes', $_REQUEST)) {
    // Send the resend Confirmation

    // Clear the State
    if (array_key_exists('noty', $state)) {
        unset($state['noty']);
    }
    // Logout
    $state['Responder'] = ['sspmod_attrauthcomanage_Auth_Logout', 'postLogout'];
    $idp = SimpleSAML_IdP::getByState($state);
    $idp->handleLogoutRequest($state, null);
    assert('FALSE');
}
// XXX NO/Abort Action SECTION
if(array_key_exists('no', $_REQUEST)) {
    $state['Responder'] = ['sspmod_attrauthcomanage_Auth_Logout', 'postLogout'];
    $idp = SimpleSAML_IdP::getByState($state);
    $idp->handleLogoutRequest($state, null);
    assert('FALSE');
}

// BEFORE RENDER SECTION
$globalConfig = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($globalConfig, 'attrauthcomanage:noty.tpl.php');
// Redirect on this controller on Yes click
$t->data['yesTarget'] = SimpleSAML_Module::getModuleURL('attrauthcomanage/noty.ctrl.php');
$t->data['yesData'] = array('StateId' => $id);
// Abort Action cofigure
$t->data['logoutLink'] = SimpleSAML_Module::getModuleURL('attrauthcomanage/noty.ctrl.php');
$t->data['logoutData'] = array('StateId' => $id);
// Pass attributes into the View
$t->data['noty'] = $state['noty'];
// Fetch privacypolicy
$t->data['dstMetadata'] = $state['Destination'];
// Get the spEntityId for the privace policy section
if (array_key_exists('core:SP', $state)) {
    $spentityid = $state['core:SP'];
} else if (array_key_exists('saml:sp:State', $state)) {
    $spentityid = $state['saml:sp:State']['core:SP'];
} else {
    $spentityid = 'UNKNOWN';
}
// Get the Privacy Policy
if (array_key_exists('privacypolicy', $state['Destination'])) {
    $privacypolicy = $state['Destination']['privacypolicy'];
} elseif (array_key_exists('privacypolicy', $state['Source'])) {
    $privacypolicy = $state['Source']['privacypolicy'];
} else {
    $privacypolicy = false;
}
if ($privacypolicy !== false) {
    $privacypolicy = str_replace(
        '%SPENTITYID%',
        urlencode($spentityid),
        $privacypolicy
    );
}
$t->data['sppp'] = $privacypolicy;
$t->show();