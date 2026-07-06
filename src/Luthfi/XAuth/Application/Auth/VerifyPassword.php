<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Auth;

use Generator;
use Luthfi\XAuth\Domain\Exception\NotRegisteredException;
use Luthfi\XAuth\Domain\User\UserRepository;
use Luthfi\XAuth\Domain\User\PasswordHasher;

class VerifyPassword {

    public function __construct(
        private UserRepository $userRepository,
        private PasswordHasher $passwordHasher,
    ) {}

    public function check(string $playerName, string $password): Generator {
        $playerData = yield from $this->userRepository->findByName($playerName);
        if ($playerData === null) {
            throw new NotRegisteredException();
        }

        return $this->passwordHasher->verifyPassword($password, $playerData->getPasswordHash()->value());
    }
}
