<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Session;

use Generator;
use Luthfi\XAuth\Domain\Session\Session;
use Luthfi\XAuth\Domain\Session\SessionRepository;

class RestoreSession {

    public function __construct(
        private SessionRepository $sessionRepository,
    ) {}

    public function findMatching(array $sessions, string $ip, string $deviceId, int $securityLevel): ?string {
        foreach ($sessions as $sessionId => $sessionData) {
            if ($sessionData->isExpired()) {
                continue;
            }

            $ipMatch = $sessionData->getIpAddress() === $ip;
            $deviceIdMatch = $sessionData->getDeviceId()->value() === $deviceId;

            if (($securityLevel === 1 && $ipMatch && $deviceIdMatch) || ($securityLevel === 0 && $ipMatch)) {
                return $sessionId;
            }
        }

        return null;
    }

    public function findByPlayer(string $playerName): Generator {
        return yield from $this->sessionRepository->findAllByPlayer($playerName);
    }
}
