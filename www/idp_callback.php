<?php
/**
  * @author Ioannis Igoumenos <ioigoume@admin.grnet.com>
 */
if (!array_key_exists('stateId', $_REQUEST)) {
  throw new SimpleSAML_Error_BadRequest('Missing required stateId query parameter.');
}
$state = SimpleSAML_Auth_ProcessingChain::fetchProcessedState($_REQUEST['stateId']);
assert('is_array($state)');
$func = $state['ReturnProc'];
assert('is_callable($func)');
call_user_func($func, $state);
