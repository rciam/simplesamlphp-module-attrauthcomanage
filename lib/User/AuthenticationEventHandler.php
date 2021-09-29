<?php

  declare(strict_types=1);

  namespace SimpleSAML\Module\attrauthcomanage\User;

  use Exception;
  use PDO;
  use SimpleSAML\Error;
  use SimpleSAML\Logger;
  use SimpleSAML\Database;
  use SimpleSAML\Module\attrauthcomanage\Enums\AuthenticationEventTypeEnum as AuthEventEnum;

  class AuthenticationEventHandler
  {
    /**
     * @var string[]
     */
    private $fields = ['authenticated_identifier', 'authentication_event', 'remote_ip', 'created', 'modified'];

    /**
     * @var string[]
     */
    private $conflict_fields = ['authenticated_identifier', 'authentication_event'];

    /**
     * Get Model columns
     *
     * @return string[]
     */
    public function getFields(): array
    {
      return $this->fields;
    }

    /**
     * Get unique combination fields
     *
     * @return string[]
     */
    public function getConflictFields(): array
    {
      return $this->conflict_fields;
    }

    /**
     * Update the authentication event record
     *
     * @param   string  $identifier
     *
     * @return bool
     * @throws Exception
     */
    public function recordAuthenticationEvent($identifier): bool
    {
      $record = $this->getLastAuthenticationEvent($identifier);
      Logger::debug("[attrauthcomanage] recordAuthenticationEvent: record = " . var_export($record, true));
      if (!empty($record)) {
        return $this->updateAuthenticationEventModified($record[0]['id']);
      } else {
        return $this->insertAuthenticationEvent($identifier);
      }
    }

    /**
     * @param $identifier
     *
     * @return bool
     * @throws Exception
     */
    private function insertAuthenticationEvent($identifier): bool
    {
      $date = $this->getDateNow();
      // Construct a table with the values to insert
      $values = [
        $identifier,                  // Identifier
        AuthEventEnum::UserLogin,     // Event type
        $_SERVER['HTTP_X_REAL_IP'],   // IP
        $date,                        // created
        $date,                        // modified
      ];

      // Create my query parameters array
      $queryParams = array_combine($this->fields, $values);

      // Construct the query placeholders
      $placeholders = array_map(static function ($field) {
        return ':' . $field;
      }, $this->fields);

      // XXX We are using a new event type which is currently not in the database.
      $insertAuthEventquery = "INSERT INTO cm_authentication_events (" . implode(', ', $this->fields) . ")" .
        " VALUES (" . implode(', ', $placeholders) . ")";

      Logger::debug(
        '[attrauthcomanage] insertAuthenticationEvent: query template: ' . var_export(
          $insertAuthEventquery,
          true
        )
      );

      Logger::debug(
        '[attrauthcomanage] insertAuthenticationEvent: query params: ' . var_export(
          $queryParams,
          true
        )
      );

      $db = Database::getInstance();
      if (!$db->write($insertAuthEventquery, $queryParams)) {
        Logger::error(
          '[attrauthcomanage] insertAuthenticationEvent: Failed to communicate with COmanage Registry: ' . var_export(
            $db->getLastError(),
            true
          )
        );

        return false;
      }

      return true;
    }


    /**
     * @param $id        AuthenticationEvent record Id
     *
     * @return bool
     * @throws Exception
     */
    private function updateAuthenticationEventModified($id): bool
    {
      $date = $this->getDateNow();

      // XXX We are using a new event type which is currently not in the database.
      $updateAuthEventquery = "UPDATE cm_authentication_events SET modified = :modified where id = :id";
      $queryParams          = [
        'modified' => [$date, PDO::PARAM_STR],
        'id'       => [$id, PDO::PARAM_INT],
      ];

      $db = Database::getInstance();
      if (!$db->write($updateAuthEventquery, $queryParams)) {
        Logger::error(
          '[attrauthcomanage] updateAuthenticationEventModified: Failed to communicate with COmanage Registry: ' . var_export(
            $db->getLastError(),
            true
          )
        );

        return false;
      }

      return true;
    }

    /**
     * @param $identifier
     *
     * @return array        Authentication Event record
     * @throws Exception
     */
    public function getLastAuthenticationEvent($identifier): array
    {
      $getAuthEventQuery = "SELECT *"
        . " FROM cm_authentication_events AS cae"
        . " WHERE cae.authenticated_identifier = :identifier"
        . " AND cae.authentication_event = '" . AuthEventEnum::UserLogin . "'"
        . " ORDER BY cae.modified DESC"
        . " LIMIT 1";

      Logger::debug("[attrauthcomanage] getLastAuthenticationEvent: identifier = " . var_export($identifier, true));

      $db          = Database::getInstance();
      $queryParams = [
        'identifier' => [$identifier, PDO::PARAM_STR],
      ];
      $stmt        = $db->read($getAuthEventQuery, $queryParams);
      if ($stmt->execute()) {
        $result = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
          $result[] = $row;
        }
        Logger::debug("[attrauthcomanage] getLastAuthenticationEvent: result = " . var_export($result, true));

        return $result;
      } else {
        throw new Exception('Failed to communicate with COmanage Registry: ' . var_export($db->getLastError(), true));
      }

      return [];
    }

    /**
     * @return string
     * @throws Exception
     */
    private function getDateNow(): string
    {
      // Get the current date in UTC
      $dateTime = new \DateTime('now', new \DateTimeZone('Etc/UTC'));

      return $dateTime->format('Y-m-d H:i:s');
    }

  }
