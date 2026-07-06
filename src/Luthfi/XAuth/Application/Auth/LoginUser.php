<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Auth;

use Generator;
use Luthfi\XAuth\exception\AccountLockedException;
use Luthfi\XAuth\exception\IncorrectPasswordException;
use Luthfi\XAuth\exception\NotRegisteredException;
use Luthfi\XAuth\flow\AuthenticationContext;
use Luthfi\XAuth\repository\UserRepository;
use Luthfi\XAuth\PasswordHasher;
use Luthfi\XAuth\service\LoginThrottler;
use pocketmine\player\Player;

class LoginUser {

    /** @var array<string, true> */
    private array $authenticatedPlayers = [];

    /** @var array<string, true> */
    private array $forcePasswordChange = [];

    public function __construct(
        private UserRepository $userRepository,
        private PasswordHasher $passwordHasher,
        private LoginThrottler $loginThrottler,
        private \Luthfi\XAuth\TitleManager $titleManager,
        private \Luthfi\XAuth\FormManager $formManager,
    ) {}

    public function handle(Player $player, string $password): Generator {
        $playerData = yield from $this->userRepository->findByName($player->getName());
        if ($playerData === null) {
            throw new NotRegisteredException();
        }

        if ($playerData->isLocked()) {
            throw new AccountLockedException();
        }

        $storedPasswordHash = $playerData->getPasswordHash()->value();

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

    public function authenticate(Player $player): void {
        $this->authenticatedPlayers[strtolower($player->getName())] = true;
        $this->loginThrottler->reset($player);
    }

    public function isAuthenticated(Player $player): bool {
        return isset($this->authenticatedPlayers[strtolower($player->getName())]);
    }

    public function deauthenticate(Player $player): void {
        unset($this->authenticatedPlayers[strtolower($player->getName())]);
    }

    public function getAuthenticatedPlayerNames(): array {
        return array_keys($this->authenticatedPlayers);
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
}
