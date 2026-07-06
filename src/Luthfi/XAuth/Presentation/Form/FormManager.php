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

namespace Luthfi\XAuth\Presentation\Form;

use jojoe77777\FormAPI\CustomForm;
use Luthfi\XAuth\Application\Auth\AuthenticationFacade;
use Luthfi\XAuth\Application\Auth\LogoutOutcome;
use Luthfi\XAuth\Application\Auth\Pipeline\AuthenticationFlowManager;
use Luthfi\XAuth\Application\User\RegistrationFacade;
use Luthfi\XAuth\Domain\Event\PlayerChangePasswordEvent;
use Luthfi\XAuth\Domain\Event\PlayerPreAuthenticateEvent;
use Luthfi\XAuth\Domain\Exception\AccountLockedException;
use Luthfi\XAuth\Domain\Exception\AlreadyLoggedInException;
use Luthfi\XAuth\Domain\Exception\AlreadyRegisteredException;
use Luthfi\XAuth\Domain\Exception\IncorrectPasswordException;
use Luthfi\XAuth\Domain\Exception\NotRegisteredException;
use Luthfi\XAuth\Domain\Exception\PasswordMismatchException;
use Luthfi\XAuth\Domain\Exception\PlayerBlockedException;
use Luthfi\XAuth\Domain\Exception\RegistrationRateLimitException;
use Luthfi\XAuth\Presentation\Title\TitleService;
use ChernegaSergiy\Language\TranslatorInterface;
use pocketmine\command\utils\InvalidCommandSyntaxException;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\utils\Config;
use SOFe\AwaitGenerator\Await;
use Throwable;

class FormManager {

    public function __construct(
        private PluginBase $plugin,
        private TranslatorInterface $translator,
        private Config $configData,
        private RegistrationFacade $registrationService,
        private AuthenticationFacade $authenticationService,
        private AuthenticationFlowManager $authenticationFlowManager,
        private TitleService $titleService,
    ) {}

    /**
     * Shows the player the right prompt (login or register, form or title) after they have been logged out.
     */
    public function promptAfterLogout(Player $player, LogoutOutcome $outcome): void {
        $formsEnabled = (bool)($this->configData->getNested("forms.enabled") ?? true);

        if ($outcome === LogoutOutcome::EXISTING_USER) {
            $player->sendMessage($this->translator->translateFor($player, "messages.login_prompt"));
            if ($formsEnabled) {
                $this->sendLoginForm($player);
            } else {
                $this->titleService->sendTitle($player, "login_prompt", null, true);
            }
        } else {
            $player->sendMessage($this->translator->translateFor($player, "messages.register_prompt"));
            if ($formsEnabled) {
                $this->sendRegisterForm($player);
            } else {
                $this->titleService->sendTitle($player, "register_prompt", null, true);
            }
        }
    }

    public function sendLoginForm(Player $player, ?string $errorMessage = null): void {
        $loginFormConfig = [
            "title" => $this->translator->translateFor($player, "forms.login.title"),
            "content" => $this->translator->translateFor($player, "forms.login.content"),
            "password_label" => $this->translator->translateFor($player, "forms.login.password_label"),
            "password_placeholder" => $this->translator->translateFor($player, "forms.login.password_placeholder"),
        ];

        $form = new CustomForm(function (Player $player, ?array $data) use ($loginFormConfig): void {
            if ($data === null) {
                if ((bool)($this->configData->getNested("forms.kick-on-close") ?? false)) {
                    $player->kick($this->translator->translateFor($player, "messages.login_form_closed"));
                } else {
                    $this->sendLoginForm($player);
                }
                return;
            }

            $password = (string)($data["password"] ?? '');

            Await::g2c(
                $this->authenticationService->handleLoginRequest($player, $password),
                function () use ($player): void {
                    $context = $this->authenticationFlowManager->ensureContextExists($player);
                    $context->setLoginType(PlayerPreAuthenticateEvent::LOGIN_TYPE_MANUAL);
                    $this->authenticationFlowManager->completeStep($player, 'xauth_login');
                },
                function (Throwable $e) use ($player, $loginFormConfig): void {
                    if ($e instanceof AlreadyLoggedInException) {
                        $this->sendLoginForm($player, $this->translator->translateFor($player, "messages.already_logged_in"));
                    } elseif ($e instanceof PlayerBlockedException) {
                        $message = $this->translator->translateFor($player, "messages.login_attempts_exceeded", ['minutes' => (string)$e->getRemainingMinutes()]);
                        $bruteforceConfig = (array)$this->configData->get('bruteforce_protection');
                        $kickOnBlock = (bool)($bruteforceConfig['kick_on_block'] ?? true);
                        if ($kickOnBlock) {
                            $player->kick($message);
                        } else {
                            $this->sendLoginForm($player, $message);
                        }
                    } elseif ($e instanceof NotRegisteredException) {
                        $this->sendLoginForm($player, $this->translator->translateFor($player, "messages.not_registered"));
                    } elseif ($e instanceof AccountLockedException) {
                        $this->sendLoginForm($player, $this->translator->translateFor($player, "messages.account_locked_by_admin"));
                    } elseif ($e instanceof IncorrectPasswordException) {
                        $this->sendLoginForm($player, $this->translator->translateFor($player, "messages.incorrect_password"));
                    } else {
                        $this->sendLoginForm($player, $this->translator->translateFor($player, "messages.unexpected_error"));
                        $this->plugin->getLogger()->error("An unexpected error occurred during form login: " . $e->getMessage());
                    }
                }
            );
        });

        $form->setTitle((string)($loginFormConfig["title"]));
        $content = (string)($loginFormConfig["content"]);
        if (!empty($content)) {
            $form->addLabel($content);
        }
        if ($errorMessage !== null) {
            $form->addLabel($errorMessage);
        }
        $form->addInput((string)($loginFormConfig["password_label"]), (string)($loginFormConfig["password_placeholder"]), null, "password");
        $player->sendForm($form);
    }

    public function sendRegisterForm(Player $player, ?string $errorMessage = null): void {
        $registerFormConfig = [
            "title" => $this->translator->translateFor($player, "forms.register.title"),
            "content" => $this->translator->translateFor($player, "forms.register.content"),
            "password_label" => $this->translator->translateFor($player, "forms.register.password_label"),
            "password_placeholder" => $this->translator->translateFor($player, "forms.register.password_placeholder"),
            "confirm_password_label" => $this->translator->translateFor($player, "forms.register.confirm_password_label"),
            "confirm_password_placeholder" => $this->translator->translateFor($player, "forms.register.confirm_password_placeholder"),
        ];

        $form = new CustomForm(function (Player $player, ?array $data) use ($registerFormConfig): void {
            if ($data === null) {
                if ((bool)($this->configData->getNested("forms.kick-on-close") ?? false)) {
                    $player->kick($this->translator->translateFor($player, "messages.register_form_closed"));
                } else {
                    $this->sendRegisterForm($player);
                }
                return;
            }

            $rulesToggleEnabled = (bool)($this->configData->getNested("forms.register.rules_toggle.enabled") ?? false);
            if ($rulesToggleEnabled) {
                $rulesAccepted = (bool)($data["rules_accepted"] ?? false);
                if (!$rulesAccepted) {
                    $this->sendRegisterForm($player, $this->translator->translateFor($player, "messages.form_register_rules_not_accepted"));
                    return;
                }
            }

            $password = (string)($data["password"] ?? '');
            $confirmPassword = (string)($data["confirm_password"] ?? '');

            Await::g2c(
                $this->registrationService->handleRegistrationRequest($player, $password, $confirmPassword),
                function () use ($player): void {
                    $context = $this->authenticationFlowManager->ensureContextExists($player);
                    $context->setLoginType(PlayerPreAuthenticateEvent::LOGIN_TYPE_REGISTRATION);
                    $this->authenticationFlowManager->completeStep($player, 'xauth_register');
                },
                function (Throwable $e) use ($player): void {
                    if ($e instanceof AlreadyLoggedInException) {
                        $this->sendRegisterForm($player, $this->translator->translateFor($player, "messages.already_logged_in"));
                    } elseif ($e instanceof AlreadyRegisteredException) {
                        $this->sendRegisterForm($player, $this->translator->translateFor($player, "messages.already_registered"));
                    } elseif ($e instanceof AccountLockedException) {
                        $this->sendRegisterForm($player, $this->translator->translateFor($player, "messages.account_locked_by_admin"));
                    } elseif ($e instanceof RegistrationRateLimitException) {
                        $this->sendRegisterForm($player, $this->translator->translateFor($player, "messages.registration_ip_limit_reached"));
                    } elseif ($e instanceof PasswordMismatchException) {
                        $this->sendRegisterForm($player, $this->translator->translateFor($player, "messages.password_mismatch"));
                    } elseif ($e instanceof InvalidCommandSyntaxException) {
                        $this->sendRegisterForm($player, $e->getMessage());
                    } else {
                        $this->sendRegisterForm($player, $this->translator->translateFor($player, "messages.unexpected_error"));
                        $this->plugin->getLogger()->error("An unexpected error occurred during form registration: " . $e->getMessage());
                    }
                }
            );
        });

        $form->setTitle((string)($registerFormConfig["title"]));
        $content = (string)($registerFormConfig["content"]);
        if (!empty($content)) {
            $form->addLabel($content);
        }
        if ($errorMessage !== null) {
            $form->addLabel($errorMessage);
        }
        $rulesToggleEnabled = (bool)($this->configData->getNested("forms.register.rules_toggle.enabled") ?? false);
        if ($rulesToggleEnabled) {
            $rulesText = $this->translator->translateFor($player, "forms.register.rules_text");
            if (!empty($rulesText)) {
                $form->addLabel($rulesText);
            }
            $form->addToggle($this->translator->translateFor($player, "forms.register.rules_toggle_label"), false, "rules_accepted");
        }
        $form->addInput((string)($registerFormConfig["password_label"]), (string)($registerFormConfig["password_placeholder"]), null, "password");
        $form->addInput((string)($registerFormConfig["confirm_password_label"]), (string)($registerFormConfig["confirm_password_placeholder"]), null, "confirm_password");
        $player->sendForm($form);
    }

    public function sendChangePasswordForm(Player $player, ?string $errorMessage = null): void {
        $changePasswordFormConfig = [
            "title" => $this->translator->translateFor($player, "forms.changepassword.title"),
            "content" => $this->translator->translateFor($player, "forms.changepassword.content"),
            "old_password_label" => $this->translator->translateFor($player, "forms.changepassword.old_password_label"),
            "new_password_label" => $this->translator->translateFor($player, "forms.changepassword.new_password_label"),
            "confirm_new_password_label" => $this->translator->translateFor($player, "forms.changepassword.confirm_new_password_label"),
        ];

        $form = new CustomForm(function (Player $player, ?array $data) use ($changePasswordFormConfig): void {
            if ($data === null) {
                return;
            }

            $oldPassword = (string)($data["old_password"] ?? '');
            $newPassword = (string)($data["new_password"] ?? '');
            $confirmNewPassword = (string)($data["confirm_new_password"] ?? '');

            Await::g2c(
                $this->authenticationService->handleChangePasswordRequest($player, $oldPassword, $newPassword, $confirmNewPassword),
                function () use ($player): void {
                    $player->sendMessage($this->translator->translateFor($player, "messages.change_password_success"));
                },
                function (Throwable $e) use ($player): void {
                    if ($e instanceof IncorrectPasswordException) {
                        $this->sendChangePasswordForm($player, $this->translator->translateFor($player, "messages.incorrect_password"));
                    } elseif ($e instanceof PasswordMismatchException) {
                        $this->sendChangePasswordForm($player, $this->translator->translateFor($player, "messages.password_mismatch"));
                    } elseif ($e instanceof InvalidCommandSyntaxException) {
                        $this->sendChangePasswordForm($player, $e->getMessage());
                    } elseif ($e instanceof NotRegisteredException) {
                        $this->sendChangePasswordForm($player, $this->translator->translateFor($player, "messages.not_registered"));
                    } else {
                        $this->sendChangePasswordForm($player, $this->translator->translateFor($player, "messages.unexpected_error"));
                        $this->plugin->getLogger()->error("An unexpected error occurred during password change form: " . $e->getMessage());
                    }
                }
            );
        });

        $form->setTitle((string)($changePasswordFormConfig["title"]));
        $content = (string)($changePasswordFormConfig["content"]);
        if (!empty($content)) {
            $form->addLabel($content);
        }
        if ($errorMessage !== null) {
            $form->addLabel($errorMessage);
        }
        $form->addInput((string)($changePasswordFormConfig["old_password_label"]), "", null, "old_password");
        $form->addInput((string)($changePasswordFormConfig["new_password_label"]), "", null, "new_password");
        $form->addInput((string)($changePasswordFormConfig["confirm_new_password_label"]), "", null, "confirm_new_password");
        $player->sendForm($form);
    }

    public function sendForceChangePasswordForm(Player $player, ?string $errorMessage = null): void {
        $forceChangePasswordFormConfig = [
            "title" => $this->translator->translateFor($player, "forms.forcechangepassword.title"),
            "new_password_label" => $this->translator->translateFor($player, "forms.forcechangepassword.new_password_label"),
            "confirm_new_password_label" => $this->translator->translateFor($player, "forms.forcechangepassword.confirm_new_password_label"),
        ];

        $form = new CustomForm(function (Player $player, ?array $data) use ($forceChangePasswordFormConfig): void {
            if ($data === null) {
                if ((bool)($this->configData->getNested("forms.kick-on-close") ?? false)) {
                    $player->kick($this->translator->translateFor($player, "messages.force_change_password_closed"));
                } else {
                    $this->sendForceChangePasswordForm($player);
                }
                return;
            }

            $newPassword = (string)($data["new_password"] ?? '');
            $confirmNewPassword = (string)($data["confirm_new_password"] ?? '');

            Await::g2c(
                $this->authenticationService->handleForceChangePasswordRequest($player, $newPassword, $confirmNewPassword),
                function () use ($player): void {
                    $player->sendMessage($this->translator->translateFor($player, "messages.change_password_success"));
                },
                function (Throwable $e) use ($player): void {
                    if ($e instanceof PasswordMismatchException) {
                        $this->sendForceChangePasswordForm($player, $this->translator->translateFor($player, "messages.password_mismatch"));
                    } elseif ($e instanceof InvalidCommandSyntaxException) {
                        $this->sendForceChangePasswordForm($player, $e->getMessage());
                    } else {
                        $this->sendForceChangePasswordForm($player, $this->translator->translateFor($player, "messages.unexpected_error"));
                        $this->plugin->getLogger()->error("An unexpected error occurred during forced password change form: " . $e->getMessage());
                    }
                }
            );
        });

        $form->setTitle((string)($forceChangePasswordFormConfig["title"]));
        $form->addLabel($this->translator->translateFor($player, "messages.force_change_password_prompt"));
        if ($errorMessage !== null) {
            $form->addLabel($errorMessage);
        }
        $form->addInput((string)($forceChangePasswordFormConfig["new_password_label"]), "", null, "new_password");
        $form->addInput((string)($forceChangePasswordFormConfig["confirm_new_password_label"]), "", null, "confirm_new_password");
        $player->sendForm($form);
    }
}
