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

namespace Luthfi\XAuth\Presentation\Listener;

use Luthfi\XAuth\Application\Auth\AuthenticationFacade;
use Luthfi\XAuth\Application\Auth\Pipeline\AuthenticationFlowManager;
use Luthfi\XAuth\Domain\User\UserRepository;
use Luthfi\XAuth\Infrastructure\DeviceIdStore;
use pocketmine\plugin\PluginBase;
use pocketmine\utils\Config;
use pocketmine\event\Listener;
use pocketmine\event\player\PlayerJoinEvent;
use pocketmine\event\player\PlayerPreLoginEvent;
use pocketmine\event\player\PlayerQuitEvent;
use pocketmine\event\server\DataPacketSendEvent;
use pocketmine\network\mcpe\protocol\PlayerListPacket;
use SOFe\AwaitGenerator\Await;

class PlayerSessionListener implements Listener {

    private PluginBase $plugin;
    private AuthenticationFacade $authenticationService;

    public function __construct(PluginBase $plugin, AuthenticationFacade $authenticationService, AuthenticationFlowManager $authenticationFlowManager, Config $customMessages, DeviceIdStore $deviceIdStore, UserRepository $userRepository) {
        $this->plugin = $plugin;
        $this->authenticationService = $authenticationService;
        $this->authenticationFlowManager = $authenticationFlowManager;
        $this->customMessages = $customMessages;
        $this->deviceIdStore = $deviceIdStore;
        $this->userRepository = $userRepository;
    }

    /**
     * @param PlayerPreLoginEvent $event
     * @priority MONITOR
     */
    public function onPlayerPreLogin(PlayerPreLoginEvent $event): void {
        $ip = $event->getIp();
        $ipLimits = (array)$this->plugin->getConfig()->get('ip_limits');
        $maxJoinsPerIp = (int)($ipLimits['max_joins_per_ip'] ?? 0);

        if ($maxJoinsPerIp > 0) {
            $onlinePlayers = $this->plugin->getServer()->getOnlinePlayers();
            $ipCounts = [];
            foreach ($onlinePlayers as $player) {
                $playerIp = $player->getNetworkSession()->getIp();
                if (!isset($ipCounts[$playerIp])) {
                    $ipCounts[$playerIp] = 0;
                }
                $ipCounts[$playerIp]++;
            }

            if (isset($ipCounts[$ip]) && $ipCounts[$ip] >= $maxJoinsPerIp) {
                $message = (string)(((array)$this->customMessages->get("messages"))["ip_join_limit_exceeded"]);
                $event->setKickFlag(PlayerPreLoginEvent::KICK_FLAG_BANNED, $message);
                return;
            }
        }

        $bruteforceConfig = (array)$this->plugin->getConfig()->get('bruteforce_protection');
        $name = $event->getPlayerInfo()->getUsername();

        $extraData = $event->getPlayerInfo()->getExtraData();
        if(isset($extraData['DeviceId'])){
            $this->deviceIdStore->getAll()[strtolower($name)] = $extraData['DeviceId'];
        }

        if (!(bool)($bruteforceConfig['kick_at_pre_login'] ?? true)) {
            return;
        }

        Await::f2c(function () use ($name, $event, $bruteforceConfig) {
            if (yield from $this->userRepository->isLocked($name)) {
                $player->kick((string)($messages["account_locked_by_admin"] ?? "§cYour account has been locked by an administrator."));
                return;
            }

            $blockedUntil = yield from $this->userRepository->getBlockedUntil($name);
        });
    }

    /**
     * @param PlayerJoinEvent $event
     * @priority HIGHEST
     */
    public function onJoin(PlayerJoinEvent $event): void {
        $player = $event->getPlayer();
        $authenticationService = $this->authenticationService;

        if ($authenticationService->isPlayerAuthenticated($player)) {
            return;
        }

        $this->authenticationFlowManager->startAuthenticationFlow($player);
    }

    public function onPlayerQuit(PlayerQuitEvent $event): void {
        $lowerPlayerName = strtolower($event->getPlayer()->getName());
        unset($this->deviceIdStore->getAll()[$lowerPlayerName]);
        $this->authenticationService->handleQuit($event->getPlayer());
    }

    public function onPacketSend(DataPacketSendEvent $event): void {
        $playerListConfig = (array)$this->plugin->getConfig()->get('player_list_visibility', []);
        if ((bool)($playerListConfig['hide'] ?? true) === false) {
            return;
        }

        $packets = $event->getPackets();
        $modifiedPackets = [];
        $hasChanges = false;

        foreach ($packets as $packet) {
            if (!$packet instanceof PlayerListPacket) {
                $modifiedPackets[] = $packet;
                continue;
            }

            if ($packet->type !== PlayerListPacket::TYPE_ADD) {
                $modifiedPackets[] = $packet;
                continue;
            }

            $modifiedEntries = [];

            foreach ($packet->entries as $entry) {
                $playerName = $entry->username;
                $player = $this->plugin->getServer()->getPlayerExact($playerName);

                if ($player === null || !$this->authenticationService->isPlayerAuthenticated($player)) {
                    $hasChanges = true;
                    return;
                }

                $modifiedEntries[] = $entry;
            }

            if (empty($modifiedEntries)) {
                $hasChanges = true;
                continue;
            }

            if (count($modifiedEntries) !== count($packet->entries)) {
                $packet->entries = $modifiedEntries;
                $hasChanges = true;
            }

            $modifiedPackets[] = $packet;
        }

        if ($hasChanges) {
            $event->setPackets($modifiedPackets);
        }
    }
}
