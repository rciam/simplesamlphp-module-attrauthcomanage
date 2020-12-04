<?php
$this->data['header'] = $this->t('{attrauthcomanage:attrauthcomanage:exception_header}');

$this->includeAtTemplateBase('includes/header.php');
?>
<h1><?php echo $this->t('{attrauthcomanage:attrauthcomanage:exception_title}');?></h1>

<?php echo $this->t('{attrauthcomanage:attrauthcomanage:exception_description}');?>
<pre>

<?php
    
    /**
     * Comment out the following command to ovveride the default dictionary error definitions
     * with your own theme.
     */
    //$this->data['e'] = preg_replace('/attrauthcomanage:/','yourthememodule:', $this->data['e'], 1);
    echo (!empty($this->getTag('{'.$this->data['e'].'}')) ? $this->t('{'.$this->data['e'].'}',  $this->data['parameters']) : $this->data['e']);
?>
</pre>

<?php
$this->includeAtTemplateBase('includes/footer.php');

