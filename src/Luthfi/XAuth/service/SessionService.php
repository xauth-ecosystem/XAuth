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
use Luthfi\XAuth\Main;
use Luthfi\XAuth\repository\SessionRepository;
use pocketmine\player\Player;

class SessionService {

    private Main $plugin;
    private SessionRepository $sessionRepository;

    public function __construct(Main $plugin, SessionRepository $sessionRepository) {
        $this->plugin = $plugin;
        $this->sessionRepository = $sessionRepository;
    }

    public function handleSession(Player $player): Generator {
        $autoLoginConfig = (array)$this->plugin->getConfig()->get('auto-login', []);
        $securityLevel = (int)($autoLoginConfig['security_level'] ?? 1);
        $lowerPlayerName = strtolower($player->getName());
        $deviceId = $this->plugin->deviceIds[$lowerPlayerName] ?? null;

        if ($deviceId === null) {
            return;
        }

        $sessions = yield from $this->sessionRepository->findAllByPlayer($player->getName());
        $ip = $player->getNetworkSession()->getIp();
        $lifetime = (int)($autoLoginConfig['lifetime_seconds'] ?? 2592000);
        $refreshSession = (bool)($autoLoginConfig['refresh_session_on_login'] ?? true);

        $existingSessionId = null;
        foreach ($sessions as $sessionId => $sessionData) {
            $ipMatch = ($sessionData['ip_address'] ?? '') === $ip;
            $deviceIdMatch = ($sessionData['device_id'] ?? null) === $deviceId;

            if (($securityLevel === 1 && $ipMatch && $deviceIdMatch) || ($securityLevel === 0 && $ipMatch)) {
                $existingSessionId = $sessionId;
                break;
            }
        }

        if ($existingSessionId !== null) {
            $expiration = (int)($sessions[$existingSessionId]['expiration_time'] ?? 0);
            if ($expiration > time()) {
                // Session is valid, just refresh it.
                // Note: Authentication is already done before calling this method in finalizeAuthentication.
                
                if ($refreshSession) {
                    yield from $this->sessionRepository->refresh($existingSessionId, $lifetime);
                } else {
                    yield from $this->sessionRepository->updateLastActivity($existingSessionId);
                }
                
                $player->sendMessage((string)($this->plugin->getCustomMessages()->get("messages.auto_login_success") ?? "§aAuto-logged in successfully."));
            } else {
                yield from $this->sessionRepository->delete($existingSessionId);
                // Session expired, create new one below
                $existingSessionId = null;
            }
        }
        
        if ($existingSessionId === null) {
            $maxSessions = (int)($autoLoginConfig["max_sessions_per_player"] ?? 5);
            if ($maxSessions > 0) {
                $currentSessions = yield from $this->sessionRepository->findAllByPlayer($player->getName());
                if (count($currentSessions) >= $maxSessions) {
                    uasort($currentSessions, function($a, $b) {
                        return ($a['login_time'] ?? 0) <=> ($b['login_time'] ?? 0);
                    });
                    $sessionsToDeleteCount = count($currentSessions) - $maxSessions + 1;
                    $sessionsToDelete = array_slice(array_keys($currentSessions), 0, $sessionsToDeleteCount);
                    foreach ($sessionsToDelete as $delSessionId) {
                        yield from $this->sessionRepository->delete($delSessionId);
                    }
                }
            }
            yield from $this->sessionRepository->create($player->getName(), $ip, $deviceId, $lifetime);
        }
    }

    public function getSessionsForPlayer(string $playerName): Generator {
        return yield from $this->sessionRepository->findAllByPlayer($playerName);
    }

    public function terminateSession(string $sessionId): Generator {
        $session = yield from $this->sessionRepository->find($sessionId);
        if ($session === null) {
            return false;
        }

        yield from $this->sessionRepository->delete($sessionId);

        $playerName = (string)($session['player_name'] ?? '');
        $player = $this->plugin->getServer()->getPlayerExact($playerName);
        if ($player !== null && $this->plugin->getAuthenticationService()->isPlayerAuthenticated($player)) {
            yield from $this->plugin->getAuthenticationService()->handleLogout($player);
        }
        return true;
    }

    public function terminateAllSessionsForPlayer(string $playerName): Generator {
        yield from $this->sessionRepository->deleteAllForPlayer($playerName);

        $player = $this->plugin->getServer()->getPlayerExact($playerName);
        if ($player !== null && $this->plugin->getAuthenticationService()->isPlayerAuthenticated($player)) {
            yield from $this->plugin->getAuthenticationService()->handleLogout($player);
        }
    }

    public function cleanupExpiredSessions(): Generator {
        yield from $this->sessionRepository->cleanupExpired();
    }
}
