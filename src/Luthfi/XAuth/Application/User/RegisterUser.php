<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\User;

use Generator;
use Luthfi\XAuth\Domain\Event\PlayerRegisterEvent;
use Luthfi\XAuth\Domain\Exception\AccountLockedException;
use Luthfi\XAuth\Domain\Exception\AlreadyRegisteredException;
use Luthfi\XAuth\Domain\Exception\PasswordMismatchException;
use Luthfi\XAuth\Domain\Exception\RegistrationRateLimitException;
use Luthfi\XAuth\Domain\User\PasswordPolicy;
use Luthfi\XAuth\Domain\User\UserRepository;
use Luthfi\XAuth\Domain\User\PasswordHasher;
use Luthfi\XAuth\Infrastructure\KickTaskManager;
use pocketmine\command\utils\InvalidCommandSyntaxException;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;

class RegisterUser {

    public function __construct(
        private UserRepository $userRepository,
        private PasswordHasher $passwordHasher,
        private PluginBase $plugin,
        private PasswordPolicy $passwordPolicy,
        private KickTaskManager $kickTaskManager,
    ) {}

    public function register(Player $player, string $password, string $confirmPassword): Generator {
        if (yield from $this->userRepository->exists($player->getName())) {
            throw new AlreadyRegisteredException();
        }

        if (yield from $this->userRepository->isLocked($player->getName())) {
            throw new AccountLockedException();
        }

        $ipAddress = $player->getNetworkSession()->getIp();
        $maxRegistrations = (int)($this->plugin->getConfig()->getNested("registration.max_per_ip") ?? 0);
        if ($maxRegistrations > 0 && (yield from $this->userRepository->getRegistrationCountByIp($ipAddress)) >= $maxRegistrations) {
            throw new RegistrationRateLimitException();
        }

        if (($message = $this->passwordPolicy->validatePassword($password)) !== null) {
            throw new InvalidCommandSyntaxException($message);
        }

        if ($password !== $confirmPassword) {
            throw new PasswordMismatchException();
        }

        $this->kickTaskManager->cancel($player);
        $hashedPassword = $this->passwordHasher->hashPassword($password);
        yield from $this->userRepository->create($player, $hashedPassword);

        (new PlayerRegisterEvent($player))->call();
    }
}
