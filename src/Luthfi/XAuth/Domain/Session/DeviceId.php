<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Domain\Session;

class DeviceId {

    public function __construct(
        private string $value
    ) {
        if ($value === '') {
            throw new \InvalidArgumentException('Device ID cannot be empty');
        }
    }

    public static function fromString(string $value): self {
        return new self($value);
    }

    public function value(): string {
        return $this->value;
    }

    public function equals(self $other): bool {
        return $this->value === $other->value;
    }

    public function __toString(): string {
        return $this->value;
    }
}
