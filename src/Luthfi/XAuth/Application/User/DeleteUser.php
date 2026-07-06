<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\User;

use Generator;
use Luthfi\XAuth\Domain\Event\PlayerUnregisterEvent;
use Luthfi\XAuth\exception\ConfirmationExpiredException;
use Luthfi\XAuth\exception\IncorrectPasswordException;
use Luthfi\XAuth\exception\NotRegisteredException;
use Luthfi\XAuth\exception\UnregistrationNotInitiatedException;
use Luthfi\XAuth\PasswordHasher;
use Luthfi\XAuth\repository\UserRepository;
use pocketmine\player\Player;

class DeleteUser {

    /** @var array<string, int> */
    private array $confirmations = [];

    public function __construct(
        private UserRepository $userRepository,
        private PasswordHasher $passwordHasher,
        private \Luthfi\XAuth\Main $plugin,
    ) {}

    public function initiate(Player $player): void {
        $this->confirmations[strtolower($player->getName())] = time();
    }

    public function confirm(Player $player, string $password): Generator {
        $lowerName = strtolower($player->getName());

        if (!isset($this->confirmations[$lowerName])) {
            throw new UnregistrationNotInitiatedException();
        }

        if (time() - $this->confirmations[$lowerName] > 60) {
            unset($this->confirmations[$lowerName]);
            throw new ConfirmationExpiredException();
        }

        $user = yield from $this->userRepository->findByName($player->getName());

        if ($user === null || !$this->passwordHasher->verifyPassword($password, $user->getPasswordHash()->value())) {
            throw new IncorrectPasswordException();
        }

        unset($this->confirmations[$lowerName]);
        yield from $this->userRepository->delete($player->getName());
        (new PlayerUnregisterEvent($player))->call();

        $kickMessage = (string)($this->plugin->getCustomMessages()->get("messages.unregister_success_kick") ?? "§aYour account has been successfully unregistered.");
        $player->kick($kickMessage);
    }

    public function unregisterByAdmin(string $playerName): Generator {
        if (!(yield from $this->userRepository->exists($playerName))) {
            throw new NotRegisteredException();
        }

        $offlinePlayer = $this->plugin->getServer()->getOfflinePlayer($playerName);
        yield from $this->userRepository->delete($playerName);
        (new PlayerUnregisterEvent($offlinePlayer))->call();

        $player = $this->plugin->getServer()->getPlayerExact($playerName);
        if ($player !== null) {
            yield from $this->plugin->getAuthenticationService()->handleLogout($player);
            $player->sendMessage((string)(($this->plugin->getCustomMessages()->get("messages"))["account_unregistered_by_admin"] ?? "§eYour account has been unregistered by an administrator. Please register again."));
        }
    }
}
