<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Session;

use Generator;
use Luthfi\XAuth\Domain\Session\Session;
use Luthfi\XAuth\repository\SessionRepository;
use pocketmine\player\Player;

class CreateSession {

    public function __construct(
        private SessionRepository $sessionRepository,
    ) {}

    public function create(Player $player, string $deviceId, int $lifetime): Generator {
        $ip = $player->getNetworkSession()->getIp();
        return yield from $this->sessionRepository->create(
            $player->getName(),
            $ip,
            $deviceId,
            $lifetime
        );
    }

    public function enforceLimit(Player $player, int $maxSessions): Generator {
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
}
