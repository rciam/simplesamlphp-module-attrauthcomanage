<?php
$this->data['header'] = 'Error in attribute aggregation';

$this->includeAtTemplateBase('includes/header.php');
?>
<h1>Oops! Something went wrong.</h1>

An unexpected error occurred while retrieving attributes from an external attribute authority. The exception was:
<pre>

<?php
    echo $this->data['e'];
?>
</pre>

<?php
$this->includeAtTemplateBase('includes/footer.php');
