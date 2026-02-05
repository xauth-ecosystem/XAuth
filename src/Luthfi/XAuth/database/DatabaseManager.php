<?php

/*
 * 
 *  _          _   _     __  __  ____ _      __  __    _         _   _
 * | |   _   _| |_| |__ |  \/  |/ ___( )___  \ \/ /   / \  _   _| |_| |__
 * | |  | | | | __| '_ \| |\/| | |   |// __|  \  /   / _ \| | | | __| '_ \
 * | |__| |_| | |_| | | | |  | | |___  \__ \  /  \  / ___ \ |_| | |_| | | |
 * |_____\__,_|\__|_| |_|_|  |_|\____| |___/ /_/\_\/_/   \_\__,_|\__|_| |_|
 *
 * This program is free software: you can redistribute and/or modify
 * it under the terms of the CSSM Unlimited License v2.0.
 *
 * This license permits unlimited use, modification, and distribution
 * for any purpose while maintaining authorship attribution.
 *
 * The software is provided "as is" without warranty of any kind.
 *
 * @author LuthMC
 * @author Sergiy Chernega
 * @link https://chernega.eu.org/
 *
 *
 */

declare(strict_types=1);

namespace Luthfi\XAuth\database;

use Luthfi\XAuth\Main;
use Luthfi\XAuth\repository\SessionRepository;
use Luthfi\XAuth\repository\UserRepository;
use poggit\libasynql\DataConnector;

class DatabaseManager {

    private DataConnector $connector;
    private SchemaManager $schemaManager;
    private UserRepository $userRepository;
    private SessionRepository $sessionRepository;

    public function __construct(private Main $plugin, array $databaseConfig) {
        $type = (string)($databaseConfig['type'] ?? 'sqlite');
        $this->connector = ConnectorFactory::create($plugin, $type);
        
        $this->schemaManager = new SchemaManager($plugin, $this->connector);
        $this->userRepository = new UserRepository($plugin, $this->connector);
        $this->sessionRepository = new SessionRepository($plugin, $this->connector);
    }
    
    public function connect(): void {
        $this->schemaManager->initialize(true);
    }

    public function getSchemaManager(): SchemaManager {
        return $this->schemaManager;
    }

    public function getUserRepository(): UserRepository {
        return $this->userRepository;
    }

    public function getSessionRepository(): SessionRepository {
        return $this->sessionRepository;
    }
    
    public function getConnector(): DataConnector {
        return $this->connector;
    }

    public function close(): void {
        if (isset($this->connector)) {
            $this->connector->close();
        }
    }
}
