<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Auth;

use Generator;
use Luthfi\XAuth\Application\Auth\ChangePassword;
use Luthfi\XAuth\Application\Auth\LoginUser;
use Luthfi\XAuth\Application\Auth\LogoutUser;
use Luthfi\XAuth\Application\Auth\VerifyPassword;
use Luthfi\XAuth\Domain\Event\PlayerAuthenticateEvent;
use Luthfi\XAuth\Domain\Event\PlayerDeauthenticateEvent;
use Luthfi\XAuth\Domain\Exception\AlreadyLoggedInException;
use Luthfi\XAuth\Domain\Exception\NotRegisteredException;
use Luthfi\XAuth\Application\Auth\Pipeline\AuthenticationContext;
use Luthfi\XAuth\Presentation\Form\FormManager;
use Luthfi\XAuth\Main;
use Luthfi\XAuth\Application\Player\PlayerStateService;
use Luthfi\XAuth\Application\Session\SessionService;
use Luthfi\XAuth\Domain\Auth\LoginRateLimiter;
use Luthfi\XAuth\Domain\Player\VisibilityManager;
use Luthfi\XAuth\Domain\User\PasswordHasher;
use Luthfi\XAuth\Domain\Session\SessionRepository;
use Luthfi\XAuth\Domain\User\UserRepository;
use Luthfi\XAuth\Presentation\Title\TitleService;
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
    private VisibilityManager $playerVisibilityService;
    private TitleService $titleManager;
    private FormManager $formManager;
    private LoginRateLimiter $loginThrottler;
    private LoginUser $loginUser;
    private LogoutUser $logoutUser;
    private ChangePassword $changePassword;
    private VerifyPassword $verifyPassword;

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
        VisibilityManager $playerVisibilityService,
        TitleService $titleManager,
        FormManager $formManager,
        LoginRateLimiter $loginThrottler,
        LoginUser $loginUser,
        LogoutUser $logoutUser,
        ChangePassword $changePassword,
        VerifyPassword $verifyPassword
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
        $this->loginUser = $loginUser;
        $this->logoutUser = $logoutUser;
        $this->changePassword = $changePassword;
        $this->verifyPassword = $verifyPassword;
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
        yield from $this->loginUser->handle($player, $password);
    }

    public function handleChangePasswordRequest(Player $player, string $oldPassword, string $newPassword, string $confirmNewPassword): Generator {
        yield from $this->changePassword->handleForPlayer($player, $oldPassword, $newPassword, $confirmNewPassword);
    }

    public function handleChangePasswordRequestByName(string $username, string $oldPassword, string $newPassword, string $confirmNewPassword): Generator {
        yield from $this->changePassword->handleForUsername($username, $oldPassword, $newPassword, $confirmNewPassword);
    }

    public function handleForceChangePasswordRequest(Player $player, string $newPassword, string $confirmNewPassword): Generator {
        yield from $this->changePassword->handleForceForPlayer($player, $newPassword, $confirmNewPassword);
    }

    public function handleLogout(Player $player): Generator {
        $this->deauthenticatePlayer($player);
        yield from $this->logoutUser->handle($player);
        (new PlayerDeauthenticateEvent($player, false))->call();
    }

    public function handleQuit(Player $player): void {
        $this->deauthenticatePlayer($player);
        $this->logoutUser->handleQuit($player);
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

        if (($message = $this->plugin->getPasswordPolicy()->validatePassword($newPassword)) !== null) {
            throw new InvalidCommandSyntaxException($message);
        }

        $newHashedPassword = $this->passwordHasher->hashPassword($newPassword);
        $offlinePlayer = Server::getInstance()->getOfflinePlayer($playerName);
        yield from $this->userRepository->updatePassword($offlinePlayer, $newHashedPassword);
    }

    public function checkPlayerPassword(string $playerName, string $password): Generator {
        return yield from $this->verifyPassword->check($playerName, $password);
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
                $lastLoginIp = $latestSession->getIpAddress();
                $lastLoginTime = date("Y-m-d H:i:s", $latestSession->getLoginTime());
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
