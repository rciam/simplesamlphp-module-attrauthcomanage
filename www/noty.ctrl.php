<?php
use SimpleSAML\Auth;
use SimpleSAML\Logger;
use SimpleSAML\Error;
use SimpleSAML\XHTML;
use SimpleSAML\Module;
use SimpleSAML\Configuration;
use SimpleSAML\Module\attrauthcomanage\Tools\Utils as Utils;

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new Error\BadRequest(
        'Missing required StateId query parameter.'
    );
}
$id = $_REQUEST['StateId'];
/* Restore state */
$state = Auth\State::loadState($id, 'attrauthcomanage_noty_state');


// XXX Get Noty Configuration from state
if (!array_key_exists('noty', $state)) {
    throw new Error\Assertion(
        'Missing required noty state parameter.'
    );
}
Logger::debug("noty REQUEST => ". var_export($_REQUEST, true));

// Handle AJAX request from Send Email action
$is_ajax = 'xmlhttprequest' == strtolower( $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '' );

// XXX YES/CONFIRM Action SECTION
if ($is_ajax && array_key_exists('yes', $_REQUEST)) {
    // Resend Confirmation and return
    $mail = $_REQUEST['mail'];
    // XXX COmanage 3.1.1 does not support configurable webroots. As a result we hardcode the
    // webroot to the default, which is `registry`
    $url = 'https://' . $_SERVER['SERVER_NAME'] . '/registry' . $_REQUEST['send_endpoint'] . '.json';
    // Create an http client and make the request
    // Send an asynchronous request.
    $client = new GuzzleHttp\Client([
        'auth' => [ $state['rciamAttributes']['comanage_api_user']['username'], $state['rciamAttributes']['comanage_api_user']['password'] ],
        'timeout'  => 5.0,
    ]);
    header('Content-Type: application/json');
    try {
        $response = $client->request('POST', $url);
        // Handle response
        $construct_header = Utils::HTTPStatus($response->getStatusCode());
        $data = [
            'msg' => $response->getReasonPhrase()
        ];
        echo json_encode($data);
    } catch(\GuzzleHttp\Exception\RequestException $e) {
        if ($e->hasResponse()) {
            $response = $e->getResponse();
            $construct_resp = Utils::HTTPStatus($response->getStatusCode());
//            echo $construct_resp;
        }
    } catch(Exception $e) {
        $construct_resp = Utils::HTTPStatus($e->getCode());
//        echo $construct_resp;
    }
    return;
}
// XXX NO/Abort Action SECTION
if(array_key_exists('no', $_REQUEST)) {
    $state['Responder'] = ['SimpleSAML\Module\attrauthcomanage\Auth\Logout', 'postLogout'];
    $idp = SimpleSAML\IdP::getByState($state);
    $idp->handleLogoutRequest($state, null);
    assert('FALSE');
}

// BEFORE RENDER SECTION
$globalConfig = Configuration::getInstance();
$t = new XHTML\Template($globalConfig, 'attrauthcomanage:noty.tpl.php');
// Redirect on this controller on Yes click
$t->data['yesTarget'] = Module::getModuleURL('attrauthcomanage/noty.ctrl.php');
$t->data['yesData'] = ['StateId' => $id];
// Abort Action cofigure
$t->data['logoutLink'] = Module::getModuleURL('attrauthcomanage/noty.ctrl.php');
$t->data['logoutData'] = ['StateId' => $id];
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

$t->show();
