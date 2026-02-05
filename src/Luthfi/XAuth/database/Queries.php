<?php

declare(strict_types=1);

namespace Luthfi\XAuth\database;

final class Queries {

    // Initialization
    public const INIT_PLAYERS = 'xauth.init_players';
    public const INIT_SESSIONS = 'xauth.init_sessions';

    // Players
    public const PLAYERS_GET = 'xauth.players.get';
    public const PLAYERS_IS_REGISTERED = 'xauth.players.is_registered';
    public const PLAYERS_REGISTER = 'xauth.players.register';
    public const PLAYERS_REGISTER_RAW = 'xauth.players.register_raw';
    public const PLAYERS_UPDATE_IP = 'xauth.players.update_ip';
    public const PLAYERS_CHANGE_PASSWORD = 'xauth.players.change_password';
    public const PLAYERS_UNREGISTER = 'xauth.players.unregister';
    public const PLAYERS_SET_LOCKED = 'xauth.players.set_locked';
    public const PLAYERS_IS_LOCKED = 'xauth.players.is_locked';
    public const PLAYERS_SET_BLOCKED_UNTIL = 'xauth.players.set_blocked_until';
    public const PLAYERS_GET_BLOCKED_UNTIL = 'xauth.players.get_blocked_until';
    public const PLAYERS_SET_MUST_CHANGE_PASSWORD = 'xauth.players.set_must_change_password';
    public const PLAYERS_GET_REGISTRATION_COUNT_BY_IP = 'xauth.players.get_registration_count_by_ip';
    public const PLAYERS_GET_TOTAL_COUNT = 'xauth.players.get_total_count';
    public const PLAYERS_GET_PAGED = 'xauth.players.get_paged';

    // Sessions
    public const SESSIONS_CREATE = 'xauth.sessions.create';
    public const SESSIONS_GET = 'xauth.sessions.get';
    public const SESSIONS_GET_BY_PLAYER = 'xauth.sessions.get_by_player';
    public const SESSIONS_DELETE = 'xauth.sessions.delete';
    public const SESSIONS_DELETE_ALL_FOR_PLAYER = 'xauth.sessions.delete_all_for_player';
    public const SESSIONS_UPDATE_LAST_ACTIVITY = 'xauth.sessions.update_last_activity';
    public const SESSIONS_REFRESH = 'xauth.sessions.refresh';
    public const SESSIONS_CLEANUP_EXPIRED = 'xauth.sessions.cleanup_expired';

    private function __construct() {}
}
