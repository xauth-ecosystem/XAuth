<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Domain\User;

class PasswordHash {

    public function __construct(
        private string $value
    ) {
        if ($value === '') {
            throw new \InvalidArgumentException('Password hash cannot be empty');
        }
    }

    public static function fromString(string $value): self {
        return new self($value);
    }

    public function value(): string {
        return $this->value;
    }

    public function __toString(): string {
        return $this->value;
    }
}
