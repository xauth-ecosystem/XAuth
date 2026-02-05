<?php

declare(strict_types=1);

namespace Luthfi\XAuth\entity;

class User {

    public function __construct(
        private string $username,
        private string $passwordHash,
        private string $ip,
        private int $registeredAt,
        private int $lastLoginAt,
        private bool $isLocked,
        private int $blockedUntil,
        private bool $mustChangePassword
    ) {}

    public static function fromArray(array $data): self {
        return new self(
            (string)($data['name'] ?? ''),
            (string)($data['password'] ?? ''),
            (string)($data['ip'] ?? ''),
            (int)($data['registered_at'] ?? 0),
            (int)($data['last_login_at'] ?? 0),
            (bool)($data['locked'] ?? false),
            (int)($data['blocked_until'] ?? 0),
            (bool)($data['must_change_password'] ?? false)
        );
    }

    public function getUsername(): string {
        return $this->username;
    }

    public function getPasswordHash(): string {
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
