<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Infrastructure;

class DeviceIdStore {

    /** @var array<string, string> */
    private array $deviceIds = [];

    public function set(string $name, string $deviceId): void {
        $this->deviceIds[$name] = $deviceId;
    }

    public function get(string $name): ?string {
        return $this->deviceIds[$name] ?? null;
    }

    public function remove(string $name): void {
        unset($this->deviceIds[$name]);
    }

    /** @return array<string, string> */
    public function &getAll(): array {
        return $this->deviceIds;
    }
}
