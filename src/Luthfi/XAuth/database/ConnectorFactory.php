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

use InvalidArgumentException;
use Luthfi\XAuth\Main;
use poggit\libasynql\DataConnector;
use poggit\libasynql\libasynql;

class ConnectorFactory {
    public static function create(Main $plugin, string $providerType): DataConnector {
        $databaseConfig = $plugin->getConfig()->get('database', []);
        
        if (!isset($databaseConfig[$providerType])) {
            throw new InvalidArgumentException("Configuration for '" . $providerType . "' not found in the 'database' section of config.yml");
        }

        $logQueries = (bool) ($databaseConfig['log_queries'] ?? false);
        
        // Prepare a specific config for libasynql without modifying the original source
        $libasynqlConfig = $databaseConfig;
        $libasynqlConfig['type'] = $providerType;
        
        return libasynql::create(
            $plugin,
            $libasynqlConfig,
            [$providerType => $providerType . ".sql"],
            $logQueries
        );
    }
}