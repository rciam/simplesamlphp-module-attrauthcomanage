<?php
/**
  * @author Ioannis Igoumenos <ioigoume@admin.grnet.com>
 */
if (!array_key_exists('stateId', $_REQUEST)) {
  throw new SimpleSAML_Error_BadRequest('Missing required stateId query parameter.');
}
$state = SimpleSAML_Auth_State::loadState($_REQUEST['stateId'], 'attrauthcomanage:register');
assert('is_array($state)');
SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
