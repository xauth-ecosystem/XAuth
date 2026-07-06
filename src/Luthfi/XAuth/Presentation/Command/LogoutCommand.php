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
use Luthfi\XAuth\Application\Auth\LogoutOutcome;
use Luthfi\XAuth\Presentation\Form\FormManager;
use ChernegaSergiy\Language\TranslatorInterface;
use pocketmine\command\Command;
use pocketmine\command\CommandSender;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\plugin\PluginOwned;
use pocketmine\plugin\PluginOwnedTrait;
use SOFe\AwaitGenerator\Await;
use Throwable;

class LogoutCommand extends Command implements PluginOwned {
    use PluginOwnedTrait;

    public function __construct(
        private readonly AuthenticationFacade $authenticationService,
        private readonly FormManager $formManager,
        private readonly TranslatorInterface $translator,
        private readonly PluginBase $plugin
    ) {
        parent::__construct(
            "logout",
            $this->translator->translate($this->translator->getDefaultLocale(), "messages.logout_command_description", [], null),
            $this->translator->translate($this->translator->getDefaultLocale(), "messages.logout_command_usage", [], null)
        );
        $this->setPermission("xauth.command.logout");
    }

    public function execute(CommandSender $sender, string $label, array $args): bool {
        $commandSettings = (array)$this->plugin->getConfig()->get("command_settings");

        if (isset($commandSettings['allow_logout_command']) && $commandSettings['allow_logout_command'] === false) {
            $sender->sendMessage($this->translator->translateFor($sender, "messages.logout_disabled"));
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

        Await::g2c(
            $this->authenticationService->handleLogout($sender),
            function(LogoutOutcome $outcome) use ($sender): void {
                $sender->sendMessage($this->translator->translateFor($sender, "messages.logout_success"));
                $this->formManager->promptAfterLogout($sender, $outcome);
            },
            function(Throwable $e) use ($sender): void {
                $sender->sendMessage($this->translator->translateFor($sender, "messages.unexpected_error"));
                $this->plugin->getLogger()->error("An unexpected error occurred during logout: " . $e->getMessage());
            }
        );

        return true;
    }
}
