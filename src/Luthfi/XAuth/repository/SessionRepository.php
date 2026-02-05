<?php

declare(strict_types=1);

namespace Luthfi\XAuth\repository;

use Generator;
use Luthfi\XAuth\Main;
use Luthfi\XAuth\database\Queries;
use poggit\libasynql\DataConnector;
use poggit\libasynql\SqlError;

class SessionRepository {

    public function __construct(
        private Main $plugin,
        private DataConnector $connector
    ) {}

    public function create(string $username, string $ip, string $deviceId, int $lifetimeSeconds): Generator {
        $sessionId = bin2hex(random_bytes(16));
        $loginTime = time();
        $expirationTime = $loginTime + $lifetimeSeconds;

        try {
            yield from $this->connector->asyncInsert(Queries::SESSIONS_CREATE, [
                'session_id' => $sessionId,
                'player_name' => strtolower($username),
                'ip_address' => $ip,
                'device_id' => $deviceId,
                'login_time' => $loginTime,
                'last_activity' => $loginTime,
                'expiration_time' => $expirationTime
            ]);
            $this->plugin->getLogger()->debug("Session {$sessionId} created for player {$username}.");
            return $sessionId;
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to create session for player {$username}: " . $error->getMessage());
            return null;
        }
    }

    public function find(string $sessionId): Generator {
        try {
            $rows = yield from $this->connector->asyncSelect(Queries::SESSIONS_GET, [
                'session_id' => $sessionId,
                'current_time' => time()
            ]);
            return count($rows) > 0 ? $rows[0] : null;
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to get session {$sessionId}: " . $error->getMessage());
            return null;
        }
    }

    public function findAllByPlayer(string $username): Generator {
        $name = strtolower($username);
        try {
            $rows = yield from $this->connector->asyncSelect(Queries::SESSIONS_GET_BY_PLAYER, [
                'player_name' => $name,
                'current_time' => time()
            ]);
            $sessions = [];
            foreach ($rows as $row) {
                $sessions[$row['session_id']] = $row;
            }
            return $sessions;
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to get sessions for player {$name}: " . $error->getMessage());
            return [];
        }
    }

    public function delete(string $sessionId): Generator {
        try {
            yield from $this->connector->asyncChange(Queries::SESSIONS_DELETE, [
                'session_id' => $sessionId
            ]);
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to delete session {$sessionId}: " . $error->getMessage());
            throw $error;
        }
    }

    public function deleteAllForPlayer(string $username): Generator {
        $name = strtolower($username);
        try {
            yield from $this->connector->asyncChange(Queries::SESSIONS_DELETE_ALL_FOR_PLAYER, [
                'player_name' => $name
            ]);
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to delete all sessions for player {$name}: " . $error->getMessage());
            throw $error;
        }
    }

    public function updateLastActivity(string $sessionId): Generator {
        try {
            yield from $this->connector->asyncChange(Queries::SESSIONS_UPDATE_LAST_ACTIVITY, [
                'session_id' => $sessionId,
                'current_time' => time()
            ]);
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to update session {$sessionId} last activity: " . $error->getMessage());
            throw $error;
        }
    }

    public function refresh(string $sessionId, int $newLifetimeSeconds): Generator {
        try {
            yield from $this->connector->asyncChange(Queries::SESSIONS_REFRESH, [
                'session_id' => $sessionId,
                'expiration_time' => time() + $newLifetimeSeconds
            ]);
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to refresh session {$sessionId}: " . $error->getMessage());
            throw $error;
        }
    }

    public function cleanupExpired(): Generator {
        try {
            yield from $this->connector->asyncChange(Queries::SESSIONS_CLEANUP_EXPIRED, [
                'current_time' => time()
            ]);
        } catch (SqlError $error) {
            $this->plugin->getLogger()->error("Failed to clean up expired sessions: " . $error->getMessage());
            throw $error;
        }
    }
}
