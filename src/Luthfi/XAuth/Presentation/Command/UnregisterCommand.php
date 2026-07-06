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
use Luthfi\XAuth\Application\User\RegistrationFacade;
use Luthfi\XAuth\Domain\Exception\ConfirmationExpiredException;
use Luthfi\XAuth\Domain\Exception\IncorrectPasswordException;
use Luthfi\XAuth\Domain\Exception\UnregistrationNotInitiatedException;
use ChernegaSergiy\Language\TranslatorInterface;
use pocketmine\command\Command;
use pocketmine\command\CommandSender;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\plugin\PluginOwned;
use pocketmine\plugin\PluginOwnedTrait;
use SOFe\AwaitGenerator\Await;
use Throwable;

class UnregisterCommand extends Command implements PluginOwned {
    use PluginOwnedTrait;

    public function __construct(
        private readonly AuthenticationFacade $authenticationService,
        private readonly RegistrationFacade $registrationService,
        private readonly TranslatorInterface $translator,
        private readonly PluginBase $plugin
    ) {
        parent::__construct(
            "unregister",
            $this->translator->translate($this->translator->getDefaultLocale(), "messages.unregister_command_description", [], null),
            $this->translator->translate($this->translator->getDefaultLocale(), "messages.unregister_command_usage", [], null)
        );
        $this->setPermission("xauth.command.unregister");
    }

    public function execute(CommandSender $sender, string $label, array $args): bool {
        $commandSettings = (array)$this->plugin->getConfig()->get("command_settings");
        if (isset($commandSettings['allow_player_self_unregister']) && $commandSettings['allow_player_self_unregister'] === false) {
            $sender->sendMessage($this->translator->translateFor($sender, "messages.unregister_disabled"));
            return false;
        }

        if (!$sender instanceof Player) {
            $sender->sendMessage($this->translator->translateFor($sender, "messages.command_only_in_game"));
            return false;
        }

        if (!$this->authenticationService->isPlayerAuthenticated($sender)) {
            $sender->sendMessage($this->translator->translateFor($sender, "messages.not_logged_in"));
            return false;
        }

        if (isset($args[0]) && strtolower($args[0]) === 'confirm') {
            if (!isset($args[1])) {
                $sender->sendMessage($this->translator->translateFor($sender, "messages.unregister_password_missing"));
                return false;
            }
            $password = $args[1];

            Await::g2c(
                $this->registrationService->confirmUnregistration($sender, $password),
                static function(): void {
                },
                function(Throwable $e) use ($sender): void {
                    switch (true) {
                        case $e instanceof UnregistrationNotInitiatedException:
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.unregister_not_initiated"));
                            break;
                        case $e instanceof ConfirmationExpiredException:
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.unregister_confirmation_expired"));
                            break;
                        case $e instanceof IncorrectPasswordException:
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.incorrect_password"));
                            break;
                        default:
                            $sender->sendMessage($this->translator->translateFor($sender, "messages.unexpected_error"));
                            $this->plugin->getLogger()->error("An unexpected error occurred during unregistration confirmation: " . $e->getMessage());
                            break;
                    }
                }
            );
        } else {
            $this->registrationService->initiateUnregistration($sender);
            $sender->sendMessage($this->translator->translateFor($sender, "messages.unregister_initiate"));
        }
        return true;
    }
}
