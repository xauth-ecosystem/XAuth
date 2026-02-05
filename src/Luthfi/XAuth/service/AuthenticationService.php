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

namespace Luthfi\XAuth\service;

use Generator;
use Luthfi\XAuth\event\PlayerAuthenticateEvent;
use Luthfi\XAuth\event\PlayerChangePasswordEvent;
use Luthfi\XAuth\event\PlayerDeauthenticateEvent;
use Luthfi\XAuth\exception\AccountLockedException;
use Luthfi\XAuth\exception\AlreadyLoggedInException;
use Luthfi\XAuth\exception\IncorrectPasswordException;
use Luthfi\XAuth\exception\NotRegisteredException;
use Luthfi\XAuth\exception\PasswordMismatchException;
use Luthfi\XAuth\flow\AuthenticationContext;
use Luthfi\XAuth\FormManager;
use Luthfi\XAuth\Main;
use Luthfi\XAuth\PasswordHasher;
use Luthfi\XAuth\repository\SessionRepository;
use Luthfi\XAuth\repository\UserRepository;
use pocketmine\command\utils\InvalidCommandSyntaxException;
use pocketmine\player\Player;
use pocketmine\Server;

class AuthenticationService {

    private Main $plugin;
    private UserRepository $userRepository;
    private SessionRepository $sessionRepository;
    private PasswordHasher $passwordHasher;
    private SessionService $sessionService;
    private PlayerStateService $playerStateService;
    private PlayerVisibilityService $playerVisibilityService;
    private TitleManager $titleManager;
    private FormManager $formManager;
    private LoginThrottler $loginThrottler;

    /** @var array<string, bool> */
    private array $authenticatedPlayers = [];

    /** @var array<string, bool> */
    private array $forcePasswordChange = [];

    public function __construct(
        Main $plugin,
        UserRepository $userRepository,
        SessionRepository $sessionRepository,
        PasswordHasher $passwordHasher,
        SessionService $sessionService,
        PlayerStateService $playerStateService,
        PlayerVisibilityService $playerVisibilityService,
        TitleManager $titleManager,
        FormManager $formManager,
        LoginThrottler $loginThrottler
    ) {
        $this->plugin = $plugin;
        $this->userRepository = $userRepository;
        $this->sessionRepository = $sessionRepository;
        $this->passwordHasher = $passwordHasher;
        $this->sessionService = $sessionService;
        $this->playerStateService = $playerStateService;
        $this->playerVisibilityService = $playerVisibilityService;
        $this->titleManager = $titleManager;
        $this->formManager = $formManager;
        $this->loginThrottler = $loginThrottler;
    }

    public function finalizeAuthentication(Player $player, AuthenticationContext $context): Generator {
        $this->titleManager->clearTitle($player);
        $this->plugin->cancelKickTask($player);
        yield from $this->userRepository->updateIp($player);
        $this->authenticatePlayer($player);

        if ((bool)$this->plugin->getConfig()->getNested('auto-login.enabled', false)) {
            yield from $this->sessionService->handleSession($player);
        }

        $this->playerStateService->restorePlayerState($player);
        $this->playerVisibilityService->updatePlayerVisibility($player);

        (new PlayerAuthenticateEvent($player, $context->getLoginType()))->call();
    }

    public function authenticatePlayer(Player $player): void {
        $this->authenticatedPlayers[strtolower($player->getName())] = true;
        $this->loginThrottler->reset($player);
    }

    public function deauthenticatePlayer(Player $player): void {
        unset($this->authenticatedPlayers[strtolower($player->getName())]);
    }

    public function isPlayerAuthenticated(Player $player): bool {
        return isset($this->authenticatedPlayers[strtolower($player->getName())]);
    }

    public function getAuthenticatedPlayers(): array {
        return array_keys($this->authenticatedPlayers);
    }

    public function handleLoginRequest(Player $player, string $password): Generator {
        if ($this->isPlayerAuthenticated($player)) {
            throw new AlreadyLoggedInException();
        }

        yield from $this->loginThrottler->checkStatus($player);

        $playerData = yield from $this->userRepository->findByName($player->getName());
        if ($playerData === null) {
            throw new NotRegisteredException();
        }

        if ($playerData->isLocked()) {
            throw new AccountLockedException();
        }

        $storedPasswordHash = $playerData->getPasswordHash();

        if (!$this->passwordHasher->verifyPassword($password, $storedPasswordHash)) {
            yield from $this->loginThrottler->logFailure($player);
            throw new IncorrectPasswordException();
        }

        if ($this->passwordHasher->needsRehash($storedPasswordHash)) {
            $newHashedPassword = $this->passwordHasher->hashPassword($password);
            yield from $this->userRepository->updatePassword($player, $newHashedPassword);
        }

        $this->loginThrottler->reset($player);
    }

    public function handleChangePasswordRequest(Player $player, string $oldPassword, string $newPassword, string $confirmNewPassword): Generator {
        $playerData = yield from $this->userRepository->findByName($player->getName());
        if ($playerData === null) {
            throw new NotRegisteredException();
        }

        $currentHashedPassword = $playerData->getPasswordHash();

        if (!$this->passwordHasher->verifyPassword($oldPassword, $currentHashedPassword)) {
            throw new IncorrectPasswordException();
        }

        if ($this->passwordHasher->needsRehash($currentHashedPassword)) {
            $currentHashedPassword = $this->passwordHasher->hashPassword($oldPassword);
            yield from $this->userRepository->updatePassword($player, $currentHashedPassword);
        }

        if (($message = $this->plugin->getPasswordValidator()->validatePassword($newPassword)) !== null) {
            throw new InvalidCommandSyntaxException($message);
        }

        if ($newPassword !== $confirmNewPassword) {
            throw new PasswordMismatchException();
        }

        $newHashedPassword = $this->passwordHasher->hashPassword($newPassword);
        yield from $this->userRepository->updatePassword($player, $newHashedPassword);
        (new PlayerChangePasswordEvent($player))->call();
    }

    public function handleChangePasswordRequestByName(string $username, string $oldPassword, string $newPassword, string $confirmNewPassword): Generator {
        $offlinePlayer = Server::getInstance()->getOfflinePlayer($username);
        $playerData = yield from $this->userRepository->findByName($username);
        if ($playerData === null) {
            throw new NotRegisteredException();
        }

        $currentHashedPassword = $playerData->getPasswordHash();

        if (!$this->passwordHasher->verifyPassword($oldPassword, $currentHashedPassword)) {
            throw new IncorrectPasswordException();
        }

        if ($this->passwordHasher->needsRehash($currentHashedPassword)) {
            $currentHashedPassword = $this->passwordHasher->hashPassword($oldPassword);
            yield from $this->userRepository->updatePassword($offlinePlayer, $currentHashedPassword);
        }

        if (($message = $this->plugin->getPasswordValidator()->validatePassword($newPassword)) !== null) {
            throw new InvalidCommandSyntaxException($message);
        }

        if ($newPassword !== $confirmNewPassword) {
            throw new PasswordMismatchException();
        }

        $newHashedPassword = $this->passwordHasher->hashPassword($newPassword);
        yield from $this->userRepository->updatePassword($offlinePlayer, $newHashedPassword);
    }

    public function handleForceChangePasswordRequest(Player $player, string $newPassword, string $confirmNewPassword): Generator {
        if (($message = $this->plugin->getPasswordValidator()->validatePassword($newPassword)) !== null) {
            throw new InvalidCommandSyntaxException($message);
        }

        if ($newPassword !== $confirmNewPassword) {
            throw new PasswordMismatchException();
        }

        $newHashedPassword = $this->passwordHasher->hashPassword($newPassword);
        yield from $this->userRepository->updatePassword($player, $newHashedPassword);
        yield from $this->userRepository->setMustChangePassword($player->getName(), false);
        $this->stopForcePasswordChange($player);

        (new PlayerChangePasswordEvent($player))->call();
    }

    public function handleLogout(Player $player): Generator {
        $this->plugin->cancelKickTask($player);
        $this->titleManager->clearTitle($player);

        $this->deauthenticatePlayer($player);

        $this->playerStateService->protectPlayer($player);
        $this->plugin->scheduleKickTask($player);

        $playerData = yield from $this->userRepository->findByName($player->getName());
        if ($playerData !== null) {
            $formsEnabled = (bool)($this->plugin->getConfig()->getNested("forms.enabled") ?? true);
            $message = (string)(((array)$this->plugin->getCustomMessages()->get("messages"))["login_prompt"] ?? "");
            $player->sendMessage($message);
            if ($formsEnabled) {
                $this->formManager->sendLoginForm($player);
            } else {
                $this->titleManager->sendTitle($player, "login_prompt", null, true);
            }
        } else {
            $formsEnabled = (bool)($this->plugin->getConfig()->getNested("forms.enabled") ?? true);
            $message = (string)(((array)$this->plugin->getCustomMessages()->get("messages"))["register_prompt"] ?? "");
            $player->sendMessage($message);
            if ($formsEnabled) {
                $this->formManager->sendRegisterForm($player);
            } else {
                $this->titleManager->sendTitle($player, "register_prompt", null, true);
            }
        }

        (new PlayerDeauthenticateEvent($player, false))->call();
    }

    public function handleQuit(Player $player): void {
        $this->plugin->cancelKickTask($player);
        $this->titleManager->clearTitle($player);

        $this->deauthenticatePlayer($player);

        $this->playerStateService->restorePlayerState($player);

        (new PlayerDeauthenticateEvent($player, true))->call();
    }

    public function startForcePasswordChange(Player $player): void {
        $this->forcePasswordChange[strtolower($player->getName())] = true;
        $this->formManager->sendForceChangePasswordForm($player);
    }

    public function stopForcePasswordChange(Player $player): void {
        unset($this->forcePasswordChange[strtolower($player->getName())]);
    }

    public function isForcingPasswordChange(Player $player): bool {
        return isset($this->forcePasswordChange[strtolower($player->getName())]);
    }

    public function forcePasswordChangeByAdmin(string $playerName): Generator {
        if (!(yield from $this->userRepository->exists($playerName))) {
            throw new NotRegisteredException();
        }

        yield from $this->userRepository->setMustChangePassword($playerName, true);

        $player = $this->plugin->getServer()->getPlayerExact($playerName);
        $forceImmediate = (bool)$this->plugin->getConfig()->getNested("command_settings.force_change_immediate", true);

        if ($player !== null && $forceImmediate) {
            $this->startForcePasswordChange($player);
        }
    }

    public function lockAccount(string $playerName): Generator {
        if (!(yield from $this->userRepository->exists($playerName))) {
            throw new NotRegisteredException();
        }
        yield from $this->userRepository->setLocked($playerName, true);
    }

    public function unlockAccount(string $playerName): Generator {
        if (!(yield from $this->userRepository->exists($playerName))) {
            throw new NotRegisteredException();
        }
        yield from $this->userRepository->setLocked($playerName, false);
    }

    public function setPlayerPassword(string $playerName, string $newPassword): Generator {
        if (!(yield from $this->userRepository->exists($playerName))) {
            throw new NotRegisteredException();
        }

        if (($message = $this->plugin->getPasswordValidator()->validatePassword($newPassword)) !== null) {
            throw new InvalidCommandSyntaxException($message);
        }

        $newHashedPassword = $this->passwordHasher->hashPassword($newPassword);
        $offlinePlayer = Server::getInstance()->getOfflinePlayer($playerName);
        yield from $this->userRepository->updatePassword($offlinePlayer, $newHashedPassword);
    }

    public function checkPlayerPassword(string $playerName, string $password): Generator {
        $playerData = yield from $this->userRepository->findByName($playerName);
        if ($playerData === null) {
            throw new NotRegisteredException();
        }

        $storedHash = $playerData->getPasswordHash();
        return $this->passwordHasher->verifyPassword($password, $storedHash);
    }

    public function getPlayerLookupData(string $playerName): Generator {
        $offlinePlayer = Server::getInstance()->getOfflinePlayer($playerName);
        $playerData = yield from $this->userRepository->findByName($playerName);

        if ($playerData === null) {
            return null;
        }

        $lastLoginIp = "N/A";
        $lastLoginTime = "N/A";

        $autoLoginEnabled = (bool)($this->plugin->getConfig()->getNested("auto-login.enabled") ?? false);
        if ($autoLoginEnabled) {
            $sessions = yield from $this->sessionRepository->findAllByPlayer($playerName);
            if (!empty($sessions)) {
                $latestSession = current($sessions);
                $lastLoginIp = (string)($latestSession['ip_address'] ?? "N/A");
                $lastLoginTime = (isset($latestSession["login_time"])) ? date("Y-m-d H:i:s", (int)$latestSession["login_time"]) : "N/A";
            }
        } else {
            $lastLoginIp = $playerData->getIp();
            $lastLoginTime = date("Y-m-d H:i:s", $playerData->getLastLoginAt());
        }

        $isPlayerLocked = yield from $this->userRepository->isLocked($playerName);

        return [
            'player_name' => $playerName,
            'registered_at' => date("Y-m-d H:i:s", $playerData->getRegisteredAt()),
            'registration_ip' => "N/A",
            'last_login_ip' => $lastLoginIp,
            'last_login_at' => $lastLoginTime,
            'locked_status' => ($isPlayerLocked ? "Yes" : "No")
        ];
    }
}
