<?php

declare(strict_types=1);

namespace Luthfi\XAuth\service;

use Generator;
use Luthfi\XAuth\Application\User\DeleteUser;
use Luthfi\XAuth\Application\User\RegisterUser;
use Luthfi\XAuth\event\PlayerRegisterEvent;
use Luthfi\XAuth\exception\AccountLockedException;
use Luthfi\XAuth\exception\AlreadyLoggedInException;
use Luthfi\XAuth\exception\AlreadyRegisteredException;
use Luthfi\XAuth\exception\ConfirmationExpiredException;
use Luthfi\XAuth\exception\IncorrectPasswordException;
use Luthfi\XAuth\exception\NotRegisteredException;
use Luthfi\XAuth\exception\PasswordMismatchException;
use Luthfi\XAuth\exception\RegistrationRateLimitException;
use Luthfi\XAuth\exception\UnregistrationNotInitiatedException;
use Luthfi\XAuth\Main;
use Luthfi\XAuth\PasswordHasher;
use pocketmine\player\Player;
use pocketmine\command\utils\InvalidCommandSyntaxException;

class RegistrationService {

    private Main $plugin;
    private RegisterUser $registerUser;
    private DeleteUser $deleteUser;

    /** @var array<string, int> */
    private array $confirmations = [];

    public function __construct(Main $plugin, RegisterUser $registerUser, DeleteUser $deleteUser) {
        $this->plugin = $plugin;
        $this->registerUser = $registerUser;
        $this->deleteUser = $deleteUser;
    }

    public function handleRegistrationRequest(Player $player, string $password, string $confirmPassword): Generator {
        if ($this->plugin->getAuthenticationService()->isPlayerAuthenticated($player)) {
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
        yield from $this->deleteUser->unregisterByAdmin($playerName);
    }
}
