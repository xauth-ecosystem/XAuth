<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Domain\User;

class User {

    public function __construct(
        private Username $username,
        private PasswordHash $passwordHash,
        private string $ip,
        private int $registeredAt,
        private int $lastLoginAt,
        private bool $isLocked,
        private int $blockedUntil,
        private bool $mustChangePassword
    ) {}

    public function getUsername(): Username {
        return $this->username;
    }

    public function getPasswordHash(): PasswordHash {
        return $this->passwordHash;
    }

    public function getIp(): string {
        return $this->ip;
    }

    public function getRegisteredAt(): int {
        return $this->registeredAt;
    }

    public function getLastLoginAt(): int {
        return $this->lastLoginAt;
    }

    public function isLocked(): bool {
        return $this->isLocked;
    }

    public function getBlockedUntil(): int {
        return $this->blockedUntil;
    }

    public function mustChangePassword(): bool {
        return $this->mustChangePassword;
    }
}
