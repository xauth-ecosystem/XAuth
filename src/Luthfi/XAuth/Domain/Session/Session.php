<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Domain\Session;

use Luthfi\XAuth\Domain\User\Username;

class Session {

    public function __construct(
        private SessionId $sessionId,
        private Username $playerName,
        private string $ipAddress,
        private DeviceId $deviceId,
        private int $loginTime,
        private int $lastActivity,
        private int $expirationTime
    ) {}

    public function getSessionId(): SessionId {
        return $this->sessionId;
    }

    public function getPlayerName(): Username {
        return $this->playerName;
    }

    public function getIpAddress(): string {
        return $this->ipAddress;
    }

    public function getDeviceId(): DeviceId {
        return $this->deviceId;
    }

    public function getLoginTime(): int {
        return $this->loginTime;
    }

    public function getLastActivity(): int {
        return $this->lastActivity;
    }

    public function getExpirationTime(): int {
        return $this->expirationTime;
    }

    public function isExpired(): bool {
        return $this->expirationTime <= time();
    }

    public function refresh(int $newLifetimeSeconds): self {
        return new self(
            $this->sessionId,
            $this->playerName,
            $this->ipAddress,
            $this->deviceId,
            $this->loginTime,
            time(),
            time() + $newLifetimeSeconds
        );
    }
}
