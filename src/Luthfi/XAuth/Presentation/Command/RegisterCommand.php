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

use Luthfi\XAuth\Application\Auth\Pipeline\AuthenticationFlowManager;
use Luthfi\XAuth\Application\User\RegistrationFacade;
use Luthfi\XAuth\Domain\Event\PlayerPreAuthenticateEvent;
use Luthfi\XAuth\Domain\Exception\AccountLockedException;
use Luthfi\XAuth\Domain\Exception\AlreadyLoggedInException;
use Luthfi\XAuth\Domain\Exception\AlreadyRegisteredException;
use Luthfi\XAuth\Domain\Exception\PasswordMismatchException;
use Luthfi\XAuth\Domain\Exception\RegistrationRateLimitException;
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

class RegisterCommand extends Command implements PluginOwned {
    use PluginOwnedTrait;

    public function __construct(
        private readonly RegistrationFacade $registrationService,
        private readonly AuthenticationFlowManager $authenticationFlowManager,
        private readonly TranslatorInterface $translator,
        private readonly PluginBase $plugin
    ) {
        parent::__construct(
            "register",
            $this->translator->translate($this->translator->getDefaultLocale(), "messages.register_command_description", [], null),
            $this->translator->translate($this->translator->getDefaultLocale(), "messages.register_command_usage", [], null)
        );
        $this->setPermission("xauth.command.register");
    }

    public function execute(CommandSender $sender, string $label, array $args): bool {
        if (!$sender instanceof Player) {
            $sender->sendMessage($this->translator->translateFor($sender, "messages.command_only_in_game"));
            return false;
        }

        if (count($args) !== 2) {
            $sender->sendMessage($this->translator->translateFor($sender, "messages.register_usage"));
            return false;
        }

        $password = (string)($args[0] ?? '');
        $confirmPassword = (string)($args[1] ?? '');

        Await::g2c(
            $this->registrationService->handleRegistrationRequest($sender, $password, $confirmPassword),
            function() use ($sender): void {
                $context = $this->authenticationFlowManager->ensureContextExists($sender);
                $context->setLoginType(PlayerPreAuthenticateEvent::LOGIN_TYPE_REGISTRATION);
                $this->authenticationFlowManager->completeStep($sender, 'xauth_register');
            },
            function(Throwable $e) use ($sender): void {
                switch (true) {
                    case $e instanceof AlreadyLoggedInException:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.already_logged_in"));
                        break;
                    case $e instanceof AlreadyRegisteredException:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.already_registered"));
                        break;
                    case $e instanceof AccountLockedException:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.account_locked_by_admin"));
                        break;
                    case $e instanceof RegistrationRateLimitException:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.registration_ip_limit_reached"));
                        break;
                    case $e instanceof PasswordMismatchException:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.password_mismatch"));
                        break;
                    case $e instanceof InvalidCommandSyntaxException:
                        $sender->sendMessage($e->getMessage());
                        break;
                    default:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.unexpected_error"));
                        $this->plugin->getLogger()->error("An unexpected error occurred during command registration: " . $e->getMessage());
                        break;
                }
            }
        );
        return true;
    }
}
