<?php

/*
 *
 *  _          _   _     __  __  ____ _      __  __    _         _   _
 * | |   _   _| |_| |__ |  \/  |/ ___( )___  \ \/ /   / \  _   _| |_| |__
 * | |  | | | | __| '_ \| |\/| | |   |// __|  \  /   / _ \| | | | __| '_ \
 * | |__| |_| | |_| | | | |  | | |___  \__ \  /  \  / ___ \ |_| | |_| | | |
 * |_____\__,_|\__|_| |_|_|  |_|\____| |___/ /_/\_\/_/   \_\__,_|\__|_| |_|
 *
 * This program is free software: you can redistribute and/or modify
 * it under the terms of the CSSM Unlimited License v2.0.
 *
 * This license permits unlimited use, modification, and distribution
 * for any purpose while maintaining authorship attribution.
 *
 * The software is provided "as is" without warranty of any kind.
 *
 * @author LuthMC
 * @author Sergiy Chernega
 * @link https://chernega.eu.org/
 *
 *
 */

declare(strict_types=1);

namespace Luthfi\XAuth\Presentation\Command;

use Luthfi\XAuth\Application\Auth\AuthenticationFacade;
use Luthfi\XAuth\Domain\Exception\IncorrectPasswordException;
use Luthfi\XAuth\Domain\Exception\NotRegisteredException;
use Luthfi\XAuth\Domain\Exception\PasswordMismatchException;
use Luthfi\XAuth\Presentation\Form\FormManager;
use ChernegaSergiy\Language\TranslatorInterface;
use pocketmine\command\Command;
use pocketmine\command\CommandSender;
use pocketmine\command\utils\InvalidCommandSyntaxException;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\plugin\PluginOwned;
use pocketmine\plugin\PluginOwnedTrait;
use SOFe\AwaitGenerator\Await;
use Throwable;

class ResetPasswordCommand extends Command implements PluginOwned {
    use PluginOwnedTrait;

    public function __construct(
        private readonly AuthenticationFacade $authenticationService,
        private readonly FormManager $formManager,
        private readonly TranslatorInterface $translator,
        private readonly PluginBase $plugin
    ) {
        parent::__construct(
            "resetpassword",
            $this->translator->translate($this->translator->getDefaultLocale(), "messages.resetpassword_command_description", [], null),
            $this->translator->translate($this->translator->getDefaultLocale(), "messages.resetpassword_command_usage", [], null)
        );
        $this->setPermission("xauth.command.resetpassword");
    }

    public function execute(CommandSender $sender, string $label, array $args): bool {
        if (!$sender instanceof Player) {
            $sender->sendMessage($this->translator->translateFor($sender, "messages.command_only_in_game"));
            return false;
        }

        $formManager = $this->formManager;
        if ($formManager !== null && empty($args)) {
            $formManager->sendChangePasswordForm($sender);
            return true;
        }

        if (count($args) !== 3) {
            $sender->sendMessage($this->getUsage());
            return false;
        }

        $oldPassword = (string)($args[0] ?? '');
        $newPassword = (string)($args[1] ?? '');
        $confirmNewPassword = (string)($args[2] ?? '');

        Await::g2c(
            $this->authenticationService->handleChangePasswordRequest($sender, $oldPassword, $newPassword, $confirmNewPassword),
            function() use ($sender): void {
                $sender->sendMessage($this->translator->translateFor($sender, "messages.change_password_success"));
            },
            function(Throwable $e) use ($sender): void {
                switch (true) {
                    case $e instanceof IncorrectPasswordException:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.incorrect_password"));
                        break;
                    case $e instanceof PasswordMismatchException:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.password_mismatch"));
                        break;
                    case $e instanceof InvalidCommandSyntaxException:
                        $sender->sendMessage($e->getMessage());
                        break;
                    case $e instanceof NotRegisteredException:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.not_registered"));
                        break;
                    default:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.unexpected_error"));
                        $this->plugin->getLogger()->error("An unexpected error occurred during password reset command: " . $e->getMessage());
                        break;
                }
            }
        );
        return true;
    }
}
