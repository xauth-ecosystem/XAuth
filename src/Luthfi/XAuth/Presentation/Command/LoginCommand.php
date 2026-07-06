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
use Luthfi\XAuth\Application\Auth\Pipeline\AuthenticationFlowManager;
use Luthfi\XAuth\Domain\Event\PlayerPreAuthenticateEvent;
use Luthfi\XAuth\Domain\Exception\AccountLockedException;
use Luthfi\XAuth\Domain\Exception\AlreadyLoggedInException;
use Luthfi\XAuth\Domain\Exception\IncorrectPasswordException;
use Luthfi\XAuth\Domain\Exception\NotRegisteredException;
use Luthfi\XAuth\Domain\Exception\PlayerBlockedException;
use ChernegaSergiy\Language\TranslatorInterface;
use pocketmine\command\Command;
use pocketmine\command\CommandSender;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\plugin\PluginOwned;
use pocketmine\plugin\PluginOwnedTrait;
use SOFe\AwaitGenerator\Await;
use Throwable;

class LoginCommand extends Command implements PluginOwned {
    use PluginOwnedTrait;

    public function __construct(
        private readonly AuthenticationFacade $authenticationService,
        private readonly AuthenticationFlowManager $authenticationFlowManager,
        private readonly TranslatorInterface $translator,
        private readonly PluginBase $plugin
    ) {
        parent::__construct(
            "login",
            $this->translator->translate($this->translator->getDefaultLocale(), "messages.login_command_description", [], null),
            $this->translator->translate($this->translator->getDefaultLocale(), "messages.login_command_usage", [], null)
        );
        $this->setPermission("xauth.command.login");
    }

    public function execute(CommandSender $sender, string $label, array $args): bool {
        if (!$sender instanceof Player) {
            $sender->sendMessage($this->translator->translateFor($sender, "messages.command_only_in_game"));
            return false;
        }

        if (count($args) !== 1) {
            $sender->sendMessage($this->translator->translateFor($sender, "messages.login_usage"));
            return false;
        }

        $password = $args[0];

        Await::g2c(
            $this->authenticationService->handleLoginRequest($sender, $password),
            function() use ($sender): void {
                $context = $this->authenticationFlowManager->ensureContextExists($sender);
                $context->setLoginType(PlayerPreAuthenticateEvent::LOGIN_TYPE_MANUAL);
                $this->authenticationFlowManager->completeStep($sender, 'xauth_login');
            },
            function(Throwable $e) use ($sender): void {
                switch (true) {
                    case $e instanceof AlreadyLoggedInException:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.already_logged_in"));
                        break;
                    case $e instanceof PlayerBlockedException:
                        $message = $this->translator->translateFor($sender, "messages.login_attempts_exceeded", ['minutes' => (string)$e->getRemainingMinutes()]);
                        $bruteforceConfig = (array)$this->plugin->getConfig()->get('bruteforce_protection');
                        $kickOnBlock = (bool)($bruteforceConfig['kick_on_block'] ?? true);
                        if ($kickOnBlock) {
                            $sender->kick($message);
                        } else {
                            $sender->sendMessage($message);
                        }
                        break;
                    case $e instanceof NotRegisteredException:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.not_registered"));
                        break;
                    case $e instanceof AccountLockedException:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.account_locked_by_admin"));
                        break;
                    case $e instanceof IncorrectPasswordException:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.incorrect_password"));
                        break;
                    default:
                        $sender->sendMessage($this->translator->translateFor($sender, "messages.unexpected_error"));
                        $this->plugin->getLogger()->error("An unexpected error occurred during login: " . $e->getMessage());
                        break;
                }
            }
        );
        return true;
    }
}
