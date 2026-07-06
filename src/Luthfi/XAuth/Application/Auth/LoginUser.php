<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Auth;

use Generator;
use Luthfi\XAuth\exception\AccountLockedException;
use Luthfi\XAuth\exception\IncorrectPasswordException;
use Luthfi\XAuth\exception\NotRegisteredException;
use Luthfi\XAuth\repository\UserRepository;
use Luthfi\XAuth\Domain\User\PasswordHasher;
use Luthfi\XAuth\Domain\Auth\LoginRateLimiter;
use pocketmine\player\Player;

class LoginUser {

    public function __construct(
        private UserRepository $userRepository,
        private PasswordHasher $passwordHasher,
        private LoginRateLimiter $loginThrottler,
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
}
