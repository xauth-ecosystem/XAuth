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

namespace Luthfi\XAuth\service;

use Generator;
use Luthfi\XAuth\repository\UserRepository;
use Luthfi\XAuth\event\PlayerAuthenticationFailedEvent;
use Luthfi\XAuth\exception\PlayerBlockedException;
use Luthfi\XAuth\Main;
use pocketmine\player\Player;

class LoginThrottler {

    private Main $plugin;
    private UserRepository $userRepository;

    /** @var array<string, array{attempts: int, last_attempt_time: int}> */
    private array $loginAttempts = [];

    public function __construct(Main $plugin, UserRepository $userRepository) {
        $this->plugin = $plugin;
        $this->userRepository = $userRepository;
    }

    public function checkStatus(Player $player): Generator {
        $bruteforceConfig = (array)$this->plugin->getConfig()->get('bruteforce_protection');
        $enabled = (bool)($bruteforceConfig['enabled'] ?? false);
        
        if (!$enabled) {
            return;
        }

        $maxAttempts = (int)($bruteforceConfig['max_attempts'] ?? 5);
        $blockTimeMinutes = (int)($bruteforceConfig['block_time_minutes'] ?? 10);

        $name = strtolower($player->getName());
        
        // Check DB block
        $blockedUntil = yield from $this->userRepository->getBlockedUntil($name);
        if ($blockedUntil > time()) {
             $remainingMinutes = (int)ceil(($blockedUntil - time()) / 60);
             throw new PlayerBlockedException($remainingMinutes);
        }

        // Check session attempts
        if (isset($this->loginAttempts[$name]) && $this->loginAttempts[$name]['attempts'] >= $maxAttempts) {
             throw new PlayerBlockedException($blockTimeMinutes); // Or 0 if handled differently
        }
    }

    public function logFailure(Player $player): Generator {
        $name = strtolower($player->getName());
        if (!isset($this->loginAttempts[$name])) {
            $this->loginAttempts[$name] = ['attempts' => 0, 'last_attempt_time' => 0];
        }
        $this->loginAttempts[$name]['attempts']++;
        $this->loginAttempts[$name]['last_attempt_time'] = time();

        $failedAttempts = $this->loginAttempts[$name]['attempts'];
        
        // Fire event
        $event = new PlayerAuthenticationFailedEvent($player, $failedAttempts);
        $event->call();

        if ($event->isCancelled()) {
            return;
        }

        $bruteforceConfig = (array)$this->plugin->getConfig()->get('bruteforce_protection');
        $maxAttempts = (int)($bruteforceConfig['max_attempts'] ?? 5);

        if ($failedAttempts >= $maxAttempts) {
            $blockTimeMinutes = (int)($bruteforceConfig['block_time_minutes'] ?? 10);
            yield from $this->userRepository->setBlockedUntil($name, time() + ($blockTimeMinutes * 60));
            $this->reset($player);
        }
    }

    public function reset(Player $player): void {
        unset($this->loginAttempts[strtolower($player->getName())]);
    }
}
