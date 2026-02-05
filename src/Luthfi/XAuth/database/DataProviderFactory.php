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

class DataProviderFactory {
    /** @var array<string, callable> */
    private static array $providers = [
        'sqlite' => [SqliteProvider::class, 'create'],
        'mysql' => [MysqlProvider::class, 'create'],
    ];

    public static function registerProvider(string $type, callable $factory): void {
        self::$providers[strtolower($type)] = $factory;
    }

    public static function create(Main $plugin, array $config): DataProviderInterface {
        $providerType = strtolower((string)($config['type'] ?? 'sqlite'));
        $connector = ConnectorFactory::create($plugin, $providerType);
        return self::createProvider($plugin, $providerType, $connector);
    }

    public static function createProvider(Main $plugin, string $providerType, DataConnector $connector): DataProviderInterface {
        $type = strtolower($providerType);
        if (!isset(self::$providers[$type])) {
            throw new InvalidArgumentException("Invalid data provider type: " . $type);
        }
        return call_user_func(self::$providers[$type], $plugin, $connector);
    }
}