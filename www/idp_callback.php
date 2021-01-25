<?php
/**
  * @author Ioannis Igoumenos <ioigoume@admin.grnet.com>
 */
use SimpleSAML\Error;
use SimpleSAML\Auth;

if (!array_key_exists('stateId', $_REQUEST)) {
  throw new Error\BadRequest('Missing required stateId query parameter.');
}
$state = Auth\ProcessingChain::fetchProcessedState($_REQUEST['stateId']);
assert('is_array($state)');
$func = $state['ReturnProc'];
assert('is_callable($func)');

call_user_func($func, $state);
