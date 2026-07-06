<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Domain\User;

class Username {

    public function __construct(
        private string $value
    ) {
        $this->value = strtolower(trim($value));
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
