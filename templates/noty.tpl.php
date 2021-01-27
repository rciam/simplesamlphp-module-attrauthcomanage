<?php
assert('is_array($this->data["dstMetadata"])');
// Where should i go on YES click
assert('is_string($this->data["yesTarget"])');
// YES Form input entries
assert('is_array($this->data["yesData"])');
// Abort needed variables
assert('is_string($this->data["logoutLink"])');
assert('is_array($this->data["logoutData"])');
// Service Privacy Policy
assert('$this->data["sppp"] === false || is_string($this->data["sppp"])');

if (array_key_exists('name', $this->data['dstMetadata'])) {
    $dstName = $this->data['dstMetadata']['name'];
}
elseif (array_key_exists('OrganizationDisplayName', $this->data['dstMetadata'])) {
    $dstName = $this->data['dstMetadata']['OrganizationDisplayName'];
}
else {
    $dstName = $this->data['dstMetadata']['entityid'];
}

if (is_array($dstName)) {
    $dstName = $this->t($dstName);
}

// XXX Parse Parameters
$noty_level = !empty($this->data['noty']['level']) ? $this->data['noty']['level'] : 'info';
$noty_description = !empty($this->data['noty']['description']) ? $this->data['noty']['description'] : "";
$noty_status = (!empty($this->data['noty']['status'])
                && is_string($this->data['noty']['status']))
               ? $this->t('{attrauthcomanage:noty:' . $this->data['noty']['status'] . '}')
               : $this->t('{attrauthcomanage:noty:default_status}');
$yes_button_label = (!empty($this->data['noty']['ok_btn_label'])
                     && is_string($this->data['noty']['ok_btn_label']))
                    ? $this->data['noty']['ok_btn_label']
                    : $this->t('{attrauthcomanage:noty:yes}');
$yes_button_show = true;
if(isset($this->data['noty']['yes_btn_show'])
   && !is_null($this->data['noty']['yes_btn_show'])
   && is_bool($this->data['noty']['yes_btn_show'])) {
    $yes_button_show = $this->data['noty']['yes_btn_show'];
}

// XXX Get Configuration and set the loader
$globalConfig = SimpleSAML_Configuration::getInstance();
$theme_use = $globalConfig->getString('theme.use', 'default');
if ($theme_use !== 'default') {
    $theme_config_file = 'module_' . explode(':', $theme_use)[0] . '.php';
    $themeConfig       = SimpleSAML_Configuration::getConfig($theme_config_file);
    $loader = $themeConfig->getValue('loader');
    if (!empty($loader)) {
        $this->includeAtTemplateBase('includes/' . $loader . '.php');
    }
}

// XXX Set JS/CSS Dependencies
$this->data['jquery'] = array('core' => TRUE, 'ui' => TRUE, 'css' => TRUE);
$this->data['head'] = '<link rel="stylesheet" type="text/css" href="/' . $this->data['baseurlpath'] . 'module.php/attrauthcomanage/resources/css/style.css" />' . PHP_EOL;

// XXX Include Header
$this->includeAtTemplateBase('includes/header.php');

?>
    <p>
        <h3 id="attributeheader"><?php print $this->t('{attrauthcomanage:noty:title}'); ?></h3>
        <div class="<?php print $noty_level?>"><?php print $noty_status; ?></div>
        <div class="noty-description"><?php print $noty_description; ?></div>
    </p>
    <!--  Yes/Confirm Action -->
    <?php if(!empty($this->data['yesTarget']) && count($this->data['yesTarget']) > 0 && $yes_button_show): ?>
    <form style="display: inline; margin: 0px; margin-right: 0.5em; padding: 0px"
          action="<?php print htmlspecialchars($this->data['yesTarget']); ?>">
        <p style="margin: 1em">
            <?php foreach($this->data['yesData'] as $name => $value): ?>
            <input type="hidden"
                   name="<?php print htmlspecialchars($name); ?>"
                   value="<?php print htmlspecialchars($value); ?>"/>
            <?php endforeach; ?>
        </p>
        <button type="submit" name="yes" class="btn" id="yesbutton">
            <?php print htmlspecialchars($yes_button_label); ?>
        </button>
    </form>
    <?php endif; ?>

    <!-- Cancel/ Abort Action -->
    <form style="display: inline;"
          action="<?php print htmlspecialchars($this->data['logoutLink']); ?>"
          method="get">
        <?php foreach($this->data['logoutData'] as $name => $value): ?>
        <input type="hidden"
               name="<?php print htmlspecialchars($name); ?>"
               value="<?php print htmlspecialchars($value); ?>"/>
        <?php endforeach; ?>
        <button type="submit"
                class="btn-link"
                name="no"
                id="nobutton">
            <?php print htmlspecialchars($this->t('{attrauthcomanage:noty:no}')); ?>
        </button>
    </form>
    <!-- Privacy Policy -->
    <?php if ($this->data['sppp'] !== false): ?>
    <p class="service-privacy-policy"><?php print htmlspecialchars($this->t('{attrauthcomanage:attrauthcomanage:privacy_policy}')); ?>
        <a target="_blank" href="<?php print htmlspecialchars($this->data['sppp']); ?>">
          &nbsp<?php print $dstName; ?>
        </a>
    </p>
    <?php endif; ?>

<?php
// XXX Include footer
$this->includeAtTemplateBase('includes/footer.php');