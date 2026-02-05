<?php

declare(strict_types=1);

namespace Luthfi\XAuth\repository;

use Generator;
use Luthfi\XAuth\entity\User;
use Luthfi\XAuth\Main;
use Luthfi\XAuth\database\Queries;
use pocketmine\player\OfflinePlayer;
use pocketmine\player\Player;
use poggit\libasynql\DataConnector;
use poggit\libasynql\SqlError;
use SOFe\AwaitGenerator\Await;

class UserRepository {

    public function __construct(
        private Main $plugin,
        private DataConnector $connector
    ) {}

    public function findByName(string $username): Generator {
        $name = strtolower($username);
        try {
            $rows = yield from $this->connector->asyncSelect(Queries::PLAYERS_GET, ['name' => $name]);
            return count($rows) > 0 ? User::fromArray($rows[0]) : null;
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to get player data for {$name}: " . $error->getMessage());
            return null;
        }
    }

    public function exists(string $username): Generator {
        $name = strtolower($username);
        try {
            $rows = yield from $this->connector->asyncSelect(Queries::PLAYERS_IS_REGISTERED, ['name' => $name]);
            return count($rows) > 0;
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to check if player {$name} is registered: " . $error->getMessage());
            return false;
        }
    }

    public function create(Player $player, string $hashedPassword): Generator {
        $name = strtolower($player->getName());
        $ip = $player->getNetworkSession()->getIp();
        try {
            yield from $this->connector->asyncInsert(Queries::PLAYERS_REGISTER, [
                'name' => $name,
                'password' => $hashedPassword,
                'ip' => $ip,
                'registered_at' => time(),
                'registration_ip' => $ip,
                'last_login_at' => time()
            ]);
            $this->plugin->getLogger()->debug("Player {$name} registered successfully.");
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to register player {$name}: " . $error->getMessage());
            throw $error;
        }
    }

    public function updateIp(Player $player): Generator {
        $name = strtolower($player->getName());
        $ip = $player->getNetworkSession()->getIp();
        try {
            yield from $this->connector->asyncChange(Queries::PLAYERS_UPDATE_IP, [
                'name' => $name,
                'ip' => $ip,
                'last_login_at' => time()
            ]);
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to update player {$name} IP: " . $error->getMessage());
            throw $error;
        }
    }

    public function updatePassword(Player|OfflinePlayer $player, string $newHashedPassword): Generator {
        $name = strtolower($player->getName());
        try {
            yield from $this->connector->asyncChange(Queries::PLAYERS_CHANGE_PASSWORD, [
                'name' => $name,
                'password' => $newHashedPassword
            ]);
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to change player {$name} password: " . $error->getMessage());
            throw $error;
        }
    }

    public function delete(string $username): Generator {
        $name = strtolower($username);
        try {
            yield from $this->connector->asyncChange(Queries::PLAYERS_UNREGISTER, [
                'name' => $name
            ]);
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to unregister player {$name}: " . $error->getMessage());
            throw $error;
        }
    }

    public function setLocked(string $username, bool $locked): Generator {
        $name = strtolower($username);
        try {
            yield from $this->connector->asyncChange(Queries::PLAYERS_SET_LOCKED, [
                'name' => $name,
                'locked' => (int)$locked
            ]);
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to set player {$name} locked status: " . $error->getMessage());
            throw $error;
        }
    }

    public function isLocked(string $username): Generator {
        $name = strtolower($username);
        try {
            $rows = yield from $this->connector->asyncSelect(Queries::PLAYERS_IS_LOCKED, ['name' => $name]);
            return count($rows) > 0 ? (bool)($rows[0]['locked'] ?? false) : false;
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to get player {$name} locked status: " . $error->getMessage());
            return false;
        }
    }

    public function setBlockedUntil(string $username, int $timestamp): Generator {
        $name = strtolower($username);
        try {
            yield from $this->connector->asyncChange(Queries::PLAYERS_SET_BLOCKED_UNTIL, [
                'name' => $name,
                'timestamp' => $timestamp
            ]);
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to set player {$name} blocked until: " . $error->getMessage());
            throw $error;
        }
    }

    public function getBlockedUntil(string $username): Generator {
        $name = strtolower($username);
        try {
            $rows = yield from $this->connector->asyncSelect(Queries::PLAYERS_GET_BLOCKED_UNTIL, ['name' => $name]);
            return count($rows) > 0 ? (int)($rows[0]['blocked_until'] ?? 0) : 0;
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to get player {$name} blocked until: " . $error->getMessage());
            return 0;
        }
    }

    public function setMustChangePassword(string $username, bool $required): Generator {
        $name = strtolower($username);
        try {
            yield from $this->connector->asyncChange(Queries::PLAYERS_SET_MUST_CHANGE_PASSWORD, [
                'name' => $name,
                'required' => (int)$required
            ]);
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to set player {$name} must change password: " . $error->getMessage());
            throw $error;
        }
    }

    public function getRegistrationCountByIp(string $ip): Generator {
        try {
            $rows = yield from $this->connector->asyncSelect(Queries::PLAYERS_GET_REGISTRATION_COUNT_BY_IP, [
                'ip' => $ip
            ]);
            return count($rows) > 0 ? (int)($rows[0]['count'] ?? 0) : 0;
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to get registration count for IP {$ip}: " . $error->getMessage());
            return 0;
        }
    }
    
    // Methods for Migration
    public function count(): Generator {
        try {
            $rows = yield from $this->connector->asyncSelect(Queries::PLAYERS_GET_TOTAL_COUNT);
            return (int)($rows[0]['total'] ?? 0);
        } catch (SqlError $error) {
            return 0;
        }
    }

    public function getPaged(int $limit, int $offset): Generator {
        try {
            return yield from $this->connector->asyncSelect(Queries::PLAYERS_GET_PAGED, ["limit" => $limit, "offset" => $offset]);
        } catch (SqlError $error) {
            return [];
        }
    }
    
    public function createRaw(string $username, array $data): Generator {
        try {
            yield from $this->connector->asyncInsert(Queries::PLAYERS_REGISTER_RAW, [
                'name' => strtolower($username),
                'password' => $data['password'],
                'ip' => $data['ip'],
                'locked' => (int)($data['locked'] ?? false),
                'registered_at' => $data['registered_at'],
                'registration_ip' => $data['registration_ip'],
                'last_login_at' => $data['last_login_at'],
                'blocked_until' => $data['blocked_until'] ?? 0,
                'must_change_password' => (int)($data['must_change_password'] ?? false)
            ]);
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to migrate player {$username}: " . $error->getMessage());
        }
    }
}
