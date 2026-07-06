<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\User;

use Generator;
use Luthfi\XAuth\Application\Auth\AuthenticationService;
use Luthfi\XAuth\Application\User\DeleteUser;
use Luthfi\XAuth\Application\User\RegisterUser;
use Luthfi\XAuth\Domain\Event\PlayerRegisterEvent;
use Luthfi\XAuth\Domain\Exception\AccountLockedException;
use Luthfi\XAuth\Domain\Exception\AlreadyLoggedInException;
use Luthfi\XAuth\Domain\Exception\AlreadyRegisteredException;
use Luthfi\XAuth\Domain\Exception\ConfirmationExpiredException;
use Luthfi\XAuth\Domain\Exception\IncorrectPasswordException;
use Luthfi\XAuth\Domain\Exception\NotRegisteredException;
use Luthfi\XAuth\Domain\Exception\PasswordMismatchException;
use Luthfi\XAuth\Domain\Exception\RegistrationRateLimitException;
use Luthfi\XAuth\Domain\Exception\UnregistrationNotInitiatedException;
use Luthfi\XAuth\Domain\User\PasswordHasher;
use pocketmine\player\Player;
use pocketmine\command\utils\InvalidCommandSyntaxException;
use pocketmine\plugin\PluginBase;

class RegistrationService {

    private RegisterUser $registerUser;
    private DeleteUser $deleteUser;

    /** @var array<string, int> */
    private array $confirmations = [];

    public function __construct(
        private PluginBase $plugin,
        RegisterUser $registerUser,
        DeleteUser $deleteUser,
        private AuthenticationService $authenticationService,
    ) {
        $this->registerUser = $registerUser;
        $this->deleteUser = $deleteUser;
    }

    public function handleRegistrationRequest(Player $player, string $password, string $confirmPassword): Generator {
        if ($this->authenticationService->isPlayerAuthenticated($player)) {
            throw new AlreadyLoggedInException();
        }

        yield from $this->registerUser->register($player, $password, $confirmPassword);
    }

    public function initiateUnregistration(Player $player): void {
        $this->deleteUser->initiate($player);
    }

    public function confirmUnregistration(Player $player, string $password): Generator {
        yield from $this->deleteUser->confirm($player, $password);
    }

    public function unregisterPlayerByAdmin(string $playerName): Generator {
        return yield from $this->deleteUser->unregisterByAdmin($playerName);
    }
}
