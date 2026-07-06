<?php

declare(strict_types=1);

namespace Luthfi\XAuth\service;

use Generator;
use Luthfi\XAuth\Domain\Session\Session;
use Luthfi\XAuth\Domain\Session\SessionId;
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
        /** @var Session $sessionData */
        foreach ($sessions as $sessionId => $sessionData) {
            $ipMatch = $sessionData->getIpAddress() === $ip;
            $deviceIdMatch = $sessionData->getDeviceId()->value() === $deviceId;

            if (($securityLevel === 1 && $ipMatch && $deviceIdMatch) || ($securityLevel === 0 && $ipMatch)) {
                $existingSessionId = $sessionId;
                break;
            }
        }

        if ($existingSessionId !== null) {
            /** @var Session $existingSession */
            $existingSession = $sessions[$existingSessionId];
            if (!$existingSession->isExpired()) {
                if ($refreshSession) {
                    yield from $this->sessionRepository->refresh($existingSessionId, $lifetime);
                } else {
                    yield from $this->sessionRepository->updateLastActivity($existingSessionId);
                }

                $player->sendMessage((string)($this->plugin->getCustomMessages()->get("messages.auto_login_success") ?? "§aAuto-logged in successfully."));
            } else {
                yield from $this->sessionRepository->delete($existingSessionId);
                $existingSessionId = null;
            }
        }

        if ($existingSessionId === null) {
            $maxSessions = (int)($autoLoginConfig["max_sessions_per_player"] ?? 5);
            if ($maxSessions > 0) {
                $currentSessions = yield from $this->sessionRepository->findAllByPlayer($player->getName());
                if (count($currentSessions) >= $maxSessions) {
                    uasort($currentSessions, function(Session $a, Session $b) {
                        return $a->getLoginTime() <=> $b->getLoginTime();
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

        $playerName = $session->getPlayerName()->value();
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
