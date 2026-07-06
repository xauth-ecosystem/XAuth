<?php

/*
 *
 *  _          _   _     __  __  ____ _      __  __    _         _   _
 * | |   _   _| |_| |__ |  \/  |/ ___( )___  \ \/ /   / \  _   _| |_| |__
 * | |  | | | | __| '_ \| |\/| | |   |// __|  \  /   / _ \| | | | __| '_ \
 * | |__| |_| | |_| | | | |  | | |___  \__ \  /  \  / ___ \ |_| | |_| | | |
 * |_____\__,_|\__|_| |_|_|  |_|\____| |___/ /_/\_\/_/   \_\__,_|\__|_| |_|
 *
 * This program is free software: you can redistribute and/or modify
 * it under the terms of the CSSM Unlimited License v2.0.
 *
 * This license permits unlimited use, modification, and distribution
 * for any purpose while maintaining authorship attribution.
 *
 * The software is provided "as is" without warranty of any kind.
 *
 * @author LuthMC
 * @author Sergiy Chernega
 * @link https://chernega.eu.org/
 *
 *
 */

declare(strict_types=1);

namespace Luthfi\XAuth\Presentation\Command;

use Luthfi\XAuth\Application\Auth\AuthenticationFacade;
use Luthfi\XAuth\Application\Session\SessionFacade;
use Luthfi\XAuth\Application\User\RegistrationFacade;
use Luthfi\XAuth\Domain\Exception\NotRegisteredException;
use Luthfi\XAuth\Infrastructure\MigrationManager;
use Luthfi\XAuth\Infrastructure\PluginControlService;
use Luthfi\XAuth\Presentation\Form\FormManager;
use ChernegaSergiy\Language\TranslatorInterface;
use pocketmine\command\Command;
use pocketmine\command\CommandSender;
use pocketmine\command\utils\InvalidCommandSyntaxException;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\plugin\PluginOwned;
use pocketmine\plugin\PluginOwnedTrait;
use SOFe\AwaitGenerator\Await;
use Throwable;

class XAuthCommand extends Command implements PluginOwned {
    use PluginOwnedTrait;

    public function __construct(
        private readonly AuthenticationFacade $authenticationService,
        private readonly RegistrationFacade $registrationService,
        private readonly SessionFacade $sessionService,
        private readonly PluginControlService $pluginControlService,
        private readonly MigrationManager $migrationManager,
        private readonly FormManager $formManager,
        private readonly TranslatorInterface $translator,
        private readonly PluginBase $plugin
    ) {
        parent::__construct(
            "xauth",
            $this->translator->translate($this->translator->getDefaultLocale(), "messages.xauth_command_description", [], null),
            $this->translator->translate($this->translator->getDefaultLocale(), "messages.xauth_command_usage", [], null)
        );
        $this->setPermission("xauth.command.admin");
    }

    public function execute(CommandSender $sender, string $label, array $args): bool {
        if (!$this->testPermission($sender)) {
            return false;
        }

        if (count($args) < 1) {
            $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_command_usage"));
            return false;
        }

        $subCommand = strtolower((string)array_shift($args));

        switch ($subCommand) {
            case "help":
                $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_help_message"));
                break;
            case "lock":
                if (count($args) !== 1) {
                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_lock_usage"));
                    return false;
                }
                $playerName = (string)($args[0] ?? '' );
                Await::g2c(
                    $this->authenticationService->lockAccount($playerName),
                    function() use ($sender, $playerName): void {
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_player_locked", ['player_name' => $playerName]));
                    },
                    function(Throwable $e) use ($sender, $playerName): void {
                        if ($e instanceof NotRegisteredException) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.player_not_registered", ['player_name' => $playerName]));
                        } else {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.unexpected_error"));
                        }
                    }
                );
                break;
            case "unlock":
                if (count($args) !== 1) {
                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_unlock_usage"));
                    return false;
                }
                $playerName = (string)($args[0] ?? '' );
                Await::g2c(
                    $this->authenticationService->unlockAccount($playerName),
                    function() use ($sender, $playerName): void {
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_player_unlocked", ['player_name' => $playerName]));
                    },
                    function(Throwable $e) use ($sender, $playerName): void {
                        if ($e instanceof NotRegisteredException) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.player_not_registered", ['player_name' => $playerName]));
                        } else {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.unexpected_error"));
                        }
                    }
                );
                break;
            case "lookup":
                if (count($args) !== 1) {
                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_lookup_usage"));
                    return false;
                }
                $playerName = (string)($args[0] ?? '' );
                Await::g2c(
                    $this->authenticationService->getPlayerLookupData($playerName),
                    function(?array $playerData) use ($sender, $playerName): void {
                        if ($playerData === null) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.player_not_registered", ['player_name' => $playerName]));
                            return;
                        }
                        $lookupMessage = $this->translator->translateFor($sender, "messages.xauth_player_lookup_info", $playerData);
                        $sender->sendMessage($lookupMessage);
                    },
                    fn() => $sender->sendMessage($this->translator->translateFor($sender, "messages.unexpected_error"))
                );
                break;
            case "setpassword":
                if (count($args) !== 2) {
                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_setpassword_usage"));
                    return false;
                }
                $playerName = (string)($args[0] ?? '' );
                $newPassword = (string)($args[1] ?? '' );
                Await::g2c(
                    $this->authenticationService->setPlayerPassword($playerName, $newPassword),
                    function() use ($sender): void {
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.set_password_success"));
                    },
                    function(Throwable $e) use ($sender, $playerName): void {
                        if ($e instanceof NotRegisteredException) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.player_not_registered", ['player_name' => $playerName]));
                        } elseif ($e instanceof InvalidCommandSyntaxException) {
                            $sender->sendMessage($e->getMessage());
                        } else {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.unexpected_error"));
                        }
                    }
                );
                break;
            case "unregister":
                if (count($args) !== 1) {
                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_unregister_usage"));
                    return false;
                }
                $playerName = (string)($args[0] ?? '' );
                Await::g2c(
                    $this->registrationService->unregisterPlayerByAdmin($playerName),
                    function(?Player $player) use ($sender): void {
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.unregister_success"));
                        if ($player !== null) {
                            $this->formManager->promptAfterLogout($player, LogoutOutcome::NEW_USER);
                        }
                    },
                    function(Throwable $e) use ($sender, $playerName): void {
                        if ($e instanceof NotRegisteredException) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.player_not_registered", ['player_name' => $playerName]));
                        } else {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.unexpected_error"));
                        }
                    }
                );
                break;
            case "forcepasswordchange":
            case "forcepass":
                if (count($args) !== 1) {
                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_forcepasswordchange_usage"));
                    return false;
                }
                $playerName = (string)($args[0] ?? '' );
                Await::g2c(
                    $this->authenticationService->forcePasswordChangeByAdmin($playerName),
                    function(?Player $player) use ($sender, $playerName): void {
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_forcepasswordchange_success", ['player_name' => $playerName]));
                        if ($player !== null) {
                            $this->formManager->sendForceChangePasswordForm($player);
                        }
                    },
                    function(Throwable $e) use ($sender, $playerName): void {
                        if ($e instanceof NotRegisteredException) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.player_not_registered", ['player_name' => $playerName]));
                        } else {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.unexpected_error"));
                        }
                    }
                );
                break;
            case "migrate-provider":
                if (!$sender instanceof \pocketmine\console\ConsoleCommandSender) {
                    $sender->sendMessage($this->translator->translateFor($sender, "messages.command_only_in_console"));
                    return false;
                }
                if (count($args) !== 2) {
                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_migrate_usage"));
                    return false;
                }
                $sourceProviderType = strtolower($args[0]);
                $destinationProviderType = strtolower($args[1]);

                try {
                    $this->migrationManager->migrate($sourceProviderType, $destinationProviderType);
                } catch (Throwable $error) {
                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_migration_unexpected_error_prefix") . $error->getMessage());
                }
                break;
            case "status":
                if (count($args) < 1) {
                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_status_usage"));
                    return false;
                }
                $statusSubCommand = strtolower((string)array_shift($args));
                switch ($statusSubCommand) {
                    case "list":
                        $onlinePlayers = $this->plugin->getServer()->getOnlinePlayers();
                        $header = $this->translator->translateFor($sender, "messages.xauth_status_list_header", ['count' => (string)count($onlinePlayers)]);
                        $sender->sendMessage($header);
                        foreach ($onlinePlayers as $player) {
                            $status = $this->authenticationService->isPlayerAuthenticated($player) ? $this->translator->translateFor($sender, "messages.xauth_status_authenticated") : $this->translator->translateFor($sender, "messages.xauth_status_unauthenticated");
                            $sender->sendMessage("§f- " . $player->getName() . ": " . $status);
                        }
                        break;
                    case "end":
                        if (count($args) !== 1) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_status_end_usage"));
                            return false;
                        }
                        $playerName = (string)($args[0] ?? '' );
                        $player = $this->plugin->getServer()->getPlayerExact($playerName);
                        if ($player === null) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_player_not_online"));
                            return false;
                        }
                        if (!$this->authenticationService->isPlayerAuthenticated($player)) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_player_not_authenticated"));
                            return false;
                        }
                        Await::g2c(
                            $this->authenticationService->handleLogout($player),
                            function(LogoutOutcome $outcome) use ($sender, $player): void {
                                $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_status_end_success", ['player_name' => $player->getName()]));
                                $this->formManager->promptAfterLogout($player, $outcome);
                            }
                        );
                        break;
                    default:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_status_unknown_subcommand"));
                        break;
                }
                break;
            case "sessions":
                if (count($args) < 1) {
                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_sessions_usage"));
                    return false;
                }
                $sessionSubCommand = strtolower((string)array_shift($args));
                $sessionService = $this->sessionService;
                switch ($sessionSubCommand) {
                    case "list":
                        $playerName = (string)($args[0] ?? ($sender instanceof Player ? $sender->getName() : "") );
                        if (empty($playerName)) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_sessions_list_usage"));
                            return false;
                        }
                        Await::g2c(
                            $sessionService->getSessionsForPlayer($playerName),
                            function(array $sessions) use ($sender, $playerName): void {
                                if (empty($sessions)) {
                                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_sessions_no_sessions", ['player_name' => $playerName]));
                                    return;
                                }
                                $outputLines = [$this->translator->translateFor($sender, "messages.xauth_sessions_list_header", ['player_name' => $playerName, 'count' => (string)count($sessions)])];
                                foreach ($sessions as $sessionId => $session) {
                                    $sessionIdStr = $session->getSessionId()->value();
                                    $outputLines[] = $this->translator->translateFor($sender, "messages.xauth_sessions_list_entry", [
                                        'session_id' => $sessionIdStr,
                                        'ip_address' => $session->getIpAddress(),
                                        'login_time' => date("Y-m-d H:i:s", $session->getLoginTime()),
                                        'last_activity' => date("Y-m-d H:i:s", $session->getLastActivity()),
                                        'expiration_time' => date("Y-m-d H:i:s", $session->getExpirationTime())
                                    ]);
                                }
                                $sender->sendMessage(implode("\n", $outputLines));
                            }
                        );
                        break;
                    case "terminate":
                        if (count($args) !== 1) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_sessions_terminate_usage"));
                            return false;
                        }
                        $sessionId = (string)($args[0] ?? '' );
                        Await::g2c(
                            $sessionService->terminateSession($sessionId),
                            function(bool $terminated) use ($sender, $sessionId): void {
                                if ($terminated) {
                                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_sessions_terminate_success", ['session_id' => $sessionId]));
                                } else {
                                    $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_sessions_terminate_not_found"));
                                }
                            }
                        );
                        break;
                    case "terminateall":
                        $playerName = (string)($args[0] ?? ($sender instanceof Player ? $sender->getName() : "") );
                        if (empty($playerName)) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_sessions_terminateall_usage"));
                            return false;
                        }
                        Await::g2c(
                            $sessionService->terminateAllSessionsForPlayer($playerName),
                            fn() => $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_sessions_terminateall_success", ['player_name' => $playerName]))
                        );
                        break;
                    case "cleanup":
                        if (!$sender instanceof \pocketmine\console\ConsoleCommandSender) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.command_only_in_console"));
                            return false;
                        }
                        Await::g2c(
                            $sessionService->cleanupExpiredSessions(),
                            fn() => $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_sessions_cleanup_success"))
                        );
                        break;
                    default:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_sessions_unknown_subcommand"));
                        break;
                }
                break;
            case "reload":
                $this->pluginControlService->reload(fn ($p): bool => $this->authenticationService->isPlayerAuthenticated($p));
                $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_reload_success"));
                break;
            case "checkpassword":
                if (count($args) !== 2) {
                    $sender->sendMessage("§cUsage: /xauth checkpassword <player> <password>");
                    return false;
                }
                $playerName = (string)($args[0] ?? '' );
                $password = (string)($args[1] ?? '' );
                Await::g2c(
                    $this->authenticationService->checkPlayerPassword($playerName, $password),
                    function(bool $isValid) use ($sender, $playerName, $password): void {
                        $sender->sendMessage("§e--- Password Check for " . $playerName . " ---");
                        $sender->sendMessage("§fPassword to check: §e" . $password);
                        $sender->sendMessage("§fVerification Result: " . ($isValid ? "§aMATCH" : "§cNO MATCH"));
                    },
                    function(Throwable $e) use ($sender, $playerName): void {
                        if ($e instanceof NotRegisteredException) {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.player_not_registered", ['player_name' => $playerName]));
                        } else {
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.unexpected_error"));
                        }
                    }
                );
                break;
            default:
                $sender->sendMessage($this->translator->translateFor($sender, "messages.xauth_unknown_subcommand"));
                break;
        }
        return true;
    }
}
