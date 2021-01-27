<?php

$globalConfig = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($globalConfig, 'attrauthcomanage:logout.tpl.php');
$t->show();