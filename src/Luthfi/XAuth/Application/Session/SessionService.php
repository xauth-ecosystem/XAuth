<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Session;

use Generator;
use Luthfi\XAuth\Application\Session\CreateSession;
use Luthfi\XAuth\Application\Session\RestoreSession;
use Luthfi\XAuth\Application\Session\TerminateSession;
use Luthfi\XAuth\Main;
use pocketmine\player\Player;

class SessionService {

    public function __construct(
        private Main $plugin,
        private RestoreSession $restoreSession,
        private CreateSession $createSession,
        private TerminateSession $terminateSession,
    ) {}

    public function handleSession(Player $player): Generator {
        $maxSessions = (int)($this->plugin->getConfig()->getNested("auto-login.max-sessions-per-player") ?? 1);
        $securityLevel = (int)($this->plugin->getConfig()->getNested("auto-login.security-level") ?? 1);

        $sessions = yield from $this->restoreSession->findByPlayer($player->getName());

        if (!empty($sessions)) {
            $ip = $player->getNetworkSession()->getIp();
            $deviceId = (string)($this->plugin->getDeviceIds()[$player->getName()] ?? "");
            $matchingSessionId = $this->restoreSession->findMatching($sessions, $ip, $deviceId, $securityLevel);

            if ($matchingSessionId !== null) {
                yield from $this->terminateSession->terminateAllForPlayer($player->getName());
                $lifetime = (int)($this->plugin->getConfig()->getNested("auto-login.session-lifetime") ?? 86400);
                yield from $this->createSession->create($player, $deviceId, $lifetime);

                $this->plugin->getAuthenticationService()->authenticatePlayer($player);
                $this->plugin->getLogger()->debug("Auto-login: Session restored for {$player->getName()}");
                return true;
            }
        }

        yield from $this->createSession->enforceLimit($player, $maxSessions);
        $lifetime = (int)($this->plugin->getConfig()->getNested("auto-login.session-lifetime") ?? 86400);
        $deviceId = (string)($this->plugin->getDeviceIds()[$player->getName()] ?? "");
        yield from $this->createSession->create($player, $deviceId, $lifetime);
        return false;
    }

    public function handleLogoutSession(Player $player): Generator {
        $sessions = yield from $this->restoreSession->findByPlayer($player->getName());
        if (!empty($sessions)) {
            foreach ($sessions as $sessionId => $session) {
                yield from $this->terminateSession->terminate($sessionId);
            }
        }
    }
}
