<?php
use SimpleSAML\XHTML\Template;
use SimpleSAML\Configuration;

$globalConfig = Configuration::getInstance();
$t = new Template($globalConfig, 'attrauthcomanage:logout.tpl.php');
$t->show();
