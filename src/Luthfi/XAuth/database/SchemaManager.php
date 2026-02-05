<?php

declare(strict_types=1);

namespace Luthfi\XAuth\database;

use Luthfi\XAuth\Main;
use Luthfi\XAuth\database\Queries;
use poggit\libasynql\DataConnector;

class SchemaManager {

    public function __construct(
        private Main $plugin,
        private DataConnector $connector
    ) {}

    /**
     * Initializes all required database tables.
     * 
     * @param bool $wait If true, wait for all queries to complete.
     */
    public function initialize(bool $wait = true): void {
        $this->plugin->getLogger()->debug("Initializing database schema...");
        
        $this->connector->executeGeneric(Queries::INIT_PLAYERS);
        $this->connector->executeGeneric(Queries::INIT_SESSIONS);
        
        if ($wait) {
            $this->connector->waitAll();
        }
        
        $this->plugin->getLogger()->debug("Database schema initialization queries sent.");
    }
}
