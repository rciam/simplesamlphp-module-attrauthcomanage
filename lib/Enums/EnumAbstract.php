<?php
error_reporting(E_ERROR | E_PARSE);

/**
 * Class sspmod_attrauthcomanage_Enums_EnumAbstract
 */
class sspmod_attrauthcomanage_Enums_EnumAbstract
{
    /**
     * @param $type
     *
     * @return mixed
     */
    public static function getKeyType($type) {
        $value = null;
        if(!empty($type)) {
            $value = constant(get_called_class() . '::' . $type);
        }
        return $value;
    }
}