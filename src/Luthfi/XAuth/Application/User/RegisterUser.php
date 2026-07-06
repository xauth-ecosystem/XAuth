<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\User;

use Generator;
use Luthfi\XAuth\Domain\Event\PlayerRegisterEvent;
use Luthfi\XAuth\exception\AccountLockedException;
use Luthfi\XAuth\exception\AlreadyRegisteredException;
use Luthfi\XAuth\exception\PasswordMismatchException;
use Luthfi\XAuth\exception\RegistrationRateLimitException;
use Luthfi\XAuth\repository\UserRepository;
use Luthfi\XAuth\PasswordHasher;
use pocketmine\command\utils\InvalidCommandSyntaxException;
use pocketmine\player\Player;

class RegisterUser {

    public function __construct(
        private UserRepository $userRepository,
        private PasswordHasher $passwordHasher,
        private \Luthfi\XAuth\Main $plugin,
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

        if (($message = $this->plugin->getPasswordValidator()->validatePassword($password)) !== null) {
            throw new InvalidCommandSyntaxException($message);
        }

        if ($password !== $confirmPassword) {
            throw new PasswordMismatchException();
        }

        $this->plugin->cancelKickTask($player);
        $hashedPassword = $this->passwordHasher->hashPassword($password);
        yield from $this->userRepository->create($player, $hashedPassword);

        (new PlayerRegisterEvent($player))->call();
    }
}
