<?php

namespace SimpleSAML\Module\attrauthcomanage\Enums;

/**
 * Interface AuthenticationEventTypeEnum
 *
 * Authentication Event Types
 */
interface AuthenticationEventTypeEnum
{
  public const ApiLogin               = 'AI';
  public const RegistryLogin          = 'IN';
  public const UserLogin              = 'UL';
}
