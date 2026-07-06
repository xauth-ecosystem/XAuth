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
use pocketmine\command\Command;
use pocketmine\command\CommandSender;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\plugin\PluginOwned;
use pocketmine\plugin\PluginOwnedTrait;
use pocketmine\utils\Config;
use SOFe\AwaitGenerator\Await;
use Throwable;

class LoginCommand extends Command implements PluginOwned {
    use PluginOwnedTrait;

    public function __construct(
        private readonly AuthenticationFacade $authenticationService,
        private readonly AuthenticationFlowManager $authenticationFlowManager,
        private readonly Config $customMessages,
        private readonly PluginBase $plugin
    ) {
        $messages = (array)$this->customMessages->get("messages");
        parent::__construct(
            "login",
            (string)($messages["login_command_description"] ?? "Login to your account"),
            (string)($messages["login_command_usage"] ?? "/login <password>")
        );
        $this->setPermission("xauth.command.login");
    }

    public function execute(CommandSender $sender, string $label, array $args): bool {
        if (!$sender instanceof Player) {
            $sender->sendMessage((string)($this->customMessages->get("messages.command_only_in_game")));
            return false;
        }

        if (count($args) !== 1) {
            $sender->sendMessage((string)($this->customMessages->get("messages.login_usage")));
            return false;
        }

        $password = $args[0];
        $messages = (array)$this->customMessages->get("messages");

        Await::g2c(
            $this->authenticationService->handleLoginRequest($sender, $password),
            function() use ($sender): void {
                $context = $this->authenticationFlowManager->ensureContextExists($sender);
                $context->setLoginType(PlayerPreAuthenticateEvent::LOGIN_TYPE_MANUAL);
                $this->authenticationFlowManager->completeStep($sender, 'xauth_login');
            },
            function(Throwable $e) use ($sender, $messages): void {
                switch (true) {
                    case $e instanceof AlreadyLoggedInException:
                        $sender->sendMessage((string)($messages["already_logged_in"] ?? "§cYou are already logged in."));
                        break;
                    case $e instanceof PlayerBlockedException:
                        $message = (string)($messages["login_attempts_exceeded"] ?? "§cYou have exceeded the number of login attempts. Please try again in {minutes} minutes.");
                        $message = str_replace('{minutes}', (string)$e->getRemainingMinutes(), $message);
                        $bruteforceConfig = (array)$this->plugin->getConfig()->get('bruteforce_protection');
                        $kickOnBlock = (bool)($bruteforceConfig['kick_on_block'] ?? true);
                        if ($kickOnBlock) {
                            $sender->kick($message);
                        } else {
                            $sender->sendMessage($message);
                        }
                        break;
                    case $e instanceof NotRegisteredException:
                        $sender->sendMessage((string)($messages["not_registered"] ?? "§cYou are not registered. Please use /register <password> to register."));
                        break;
                    case $e instanceof AccountLockedException:
                        $sender->sendMessage((string)($messages["account_locked_by_admin"] ?? "§cYour account has been locked by an administrator."));
                        break;
                    case $e instanceof IncorrectPasswordException:
                        $sender->sendMessage((string)($messages["incorrect_password"] ?? "§cIncorrect password. Please try again."));
                        break;
                    default:
                        $sender->sendMessage((string)($messages["unexpected_error"] ?? "§cAn unexpected error occurred. Please try again."));
                        $this->plugin->getLogger()->error("An unexpected error occurred during login: " . $e->getMessage());
                        break;
                }
            }
        );
        return true;
    }
}
