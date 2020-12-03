<?php
$this->data['header'] = $this->t('{attrauthcomanage:attrauthcomanage:exception_header}');

$this->includeAtTemplateBase('includes/header.php');
?>
<h1><?php echo $this->t('{attrauthcomanage:attrauthcomanage:exception_title}');?></h1>

<?php echo $this->t('{attrauthcomanage:attrauthcomanage:exception_description}');?>
<pre>

<?php
    echo (!empty($this->getTag('{'.$this->data['e'].'}')) ? $this->t('{'.$this->data['e'].'}',  $this->data['parameters']) : $this->data['e']);
?>
</pre>

<?php
$this->includeAtTemplateBase('includes/footer.php');

