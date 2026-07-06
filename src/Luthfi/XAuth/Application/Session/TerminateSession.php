<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Session;

use Generator;
use Luthfi\XAuth\Domain\Session\SessionRepository;

class TerminateSession {

    public function __construct(
        private SessionRepository $sessionRepository,
    ) {}

    public function terminate(string $sessionId): Generator {
        $session = yield from $this->sessionRepository->find($sessionId);
        if ($session === null) {
            return false;
        }

        yield from $this->sessionRepository->delete($sessionId);
        return $session;
    }

    public function terminateAllForPlayer(string $playerName): Generator {
        yield from $this->sessionRepository->deleteAllForPlayer($playerName);
    }
}
