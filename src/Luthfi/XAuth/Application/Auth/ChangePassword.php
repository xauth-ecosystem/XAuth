<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Auth;

use Generator;
use Luthfi\XAuth\event\PlayerChangePasswordEvent;
use Luthfi\XAuth\exception\IncorrectPasswordException;
use Luthfi\XAuth\exception\NotRegisteredException;
use Luthfi\XAuth\exception\PasswordMismatchException;
use Luthfi\XAuth\repository\UserRepository;
use Luthfi\XAuth\PasswordHasher;
use pocketmine\command\utils\InvalidCommandSyntaxException;
use pocketmine\player\Player;
use pocketmine\Server;

class ChangePassword {

    public function __construct(
        private UserRepository $userRepository,
        private PasswordHasher $passwordHasher,
        private \Luthfi\XAuth\Main $plugin,
    ) {}

    public function handleForPlayer(Player $player, string $oldPassword, string $newPassword, string $confirmNewPassword): Generator {
        $playerData = yield from $this->userRepository->findByName($player->getName());
        if ($playerData === null) {
            throw new NotRegisteredException();
        }

        $currentHashedPassword = $playerData->getPasswordHash()->value();

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

    public function handleForUsername(string $username, string $oldPassword, string $newPassword, string $confirmNewPassword): Generator {
        $offlinePlayer = Server::getInstance()->getOfflinePlayer($username);
        $playerData = yield from $this->userRepository->findByName($username);
        if ($playerData === null) {
            throw new NotRegisteredException();
        }

        $currentHashedPassword = $playerData->getPasswordHash()->value();

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

    public function handleForceForPlayer(Player $player, string $newPassword, string $confirmNewPassword): Generator {
        if (($message = $this->plugin->getPasswordValidator()->validatePassword($newPassword)) !== null) {
            throw new InvalidCommandSyntaxException($message);
        }

        if ($newPassword !== $confirmNewPassword) {
            throw new PasswordMismatchException();
        }

        $newHashedPassword = $this->passwordHasher->hashPassword($newPassword);
        yield from $this->userRepository->updatePassword($player, $newHashedPassword);
        yield from $this->userRepository->setMustChangePassword($player->getName(), false);

        (new PlayerChangePasswordEvent($player))->call();
    }
}
