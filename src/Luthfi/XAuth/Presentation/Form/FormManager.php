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
use pocketmine\command\utils\InvalidCommandSyntaxException;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\utils\Config;
use SOFe\AwaitGenerator\Await;
use Throwable;

class FormManager {

    public function __construct(
        private PluginBase $plugin,
        private Config $customMessages,
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
        $messages = (array)$this->customMessages->get("messages");
        $formsEnabled = (bool)($this->configData->getNested("forms.enabled") ?? true);

        if ($outcome === LogoutOutcome::EXISTING_USER) {
            $player->sendMessage((string)($messages["login_prompt"]));
            if ($formsEnabled) {
                $this->sendLoginForm($player);
            } else {
                $this->titleService->sendTitle($player, "login_prompt", null, true);
            }
        } else {
            $player->sendMessage((string)($messages["register_prompt"]));
            if ($formsEnabled) {
                $this->sendRegisterForm($player);
            } else {
                $this->titleService->sendTitle($player, "register_prompt", null, true);
            }
        }
    }

    public function sendLoginForm(Player $player, ?string $errorMessage = null): void {
        $messages = (array)$this->customMessages->get("messages");
        $formsConfig = (array)$this->customMessages->get("forms");
        $loginFormConfig = (array)($formsConfig["login"] ?? []);

        $form = new CustomForm(function (Player $player, ?array $data) use ($messages): void {
            if ($data === null) {
                if ((bool)($this->configData->getNested("forms.kick-on-close") ?? false)) {
                    $player->kick((string)($messages["login_form_closed"] ?? "You have closed the login form."));
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
                function (Throwable $e) use ($player, $messages): void {
                    if ($e instanceof AlreadyLoggedInException) {
                        $this->sendLoginForm($player, (string)($messages["already_logged_in"] ?? "§cYou are already logged in."));
                    } elseif ($e instanceof PlayerBlockedException) {
                        $message = (string)($messages["login_attempts_exceeded"] ?? "§cYou have exceeded the number of login attempts. Please try again in {minutes} minutes.");
                        $message = str_replace('{minutes}', (string)$e->getRemainingMinutes(), $message);
                        $bruteforceConfig = (array)$this->configData->get('bruteforce_protection');
                        $kickOnBlock = (bool)($bruteforceConfig['kick_on_block'] ?? true);
                        if ($kickOnBlock) {
                            $player->kick($message);
                        } else {
                            $this->sendLoginForm($player, $message);
                        }
                    } elseif ($e instanceof NotRegisteredException) {
                        $this->sendLoginForm($player, (string)($messages["not_registered"] ?? "§cYou are not registered. Please use /register <password> to register."));
                    } elseif ($e instanceof AccountLockedException) {
                        $this->sendLoginForm($player, (string)($messages["account_locked_by_admin"] ?? "§cYour account has been locked by an administrator."));
                    } elseif ($e instanceof IncorrectPasswordException) {
                        $this->sendLoginForm($player, (string)($messages["incorrect_password"] ?? "§cIncorrect password. Please try again."));
                    } else {
                        $this->sendLoginForm($player, (string)($messages["unexpected_error"] ?? "§cAn unexpected error occurred. Please try again."));
                        $this->plugin->getLogger()->error("An unexpected error occurred during form login: " . $e->getMessage());
                    }
                }
            );
        });

        $form->setTitle((string)($loginFormConfig["title"] ?? "Login"));
        $content = (string)($loginFormConfig["content"] ?? "");
        if (!empty($content)) {
            $form->addLabel($content);
        }
        if ($errorMessage !== null) {
            $form->addLabel($errorMessage);
        }
        $form->addInput((string)($loginFormConfig["password_label"] ?? "Password"), (string)($loginFormConfig["password_placeholder"] ?? ""), null, "password");
        $player->sendForm($form);
    }

    public function sendRegisterForm(Player $player, ?string $errorMessage = null): void {
        $messages = (array)$this->customMessages->get("messages");
        $formsConfig = (array)$this->customMessages->get("forms");
        $registerFormConfig = (array)($formsConfig["register"] ?? []);

        $form = new CustomForm(function (Player $player, ?array $data) use ($messages): void {
            if ($data === null) {
                if ((bool)($this->configData->getNested("forms.kick-on-close") ?? false)) {
                    $player->kick((string)($messages["register_form_closed"] ?? "You have closed the registration form."));
                } else {
                    $this->sendRegisterForm($player);
                }
                return;
            }

            $rulesToggleEnabled = (bool)($this->configData->getNested("forms.register.rules_toggle.enabled") ?? false);
            if ($rulesToggleEnabled) {
                $rulesAccepted = (bool)($data["rules_accepted"] ?? false);
                if (!$rulesAccepted) {
                    $this->sendRegisterForm($player, (string)($messages["form_register_rules_not_accepted"]));
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
                function (Throwable $e) use ($player, $messages): void {
                    if ($e instanceof AlreadyLoggedInException) {
                        $player->sendMessage((string)($messages["already_logged_in"] ?? "§cYou are already logged in."));
                    } elseif ($e instanceof AlreadyRegisteredException) {
                        $this->sendRegisterForm($player, (string)($messages["already_registered"] ?? "§cYou are already registered. Please use /login <password> to log in."));
                    } elseif ($e instanceof AccountLockedException) {
                        $this->sendRegisterForm($player, (string)($messages["account_locked_by_admin"] ?? "§cYour account has been locked by an administrator."));
                    } elseif ($e instanceof RegistrationRateLimitException) {
                        $this->sendRegisterForm($player, (string)($messages["registration_ip_limit_reached"] ?? "§cYou have reached the maximum number of registrations for your IP address."));
                    } elseif ($e instanceof PasswordMismatchException) {
                        $this->sendRegisterForm($player, (string)($messages["password_mismatch"] ?? "§cPasswords do not match."));
                    } elseif ($e instanceof InvalidCommandSyntaxException) {
                        // This exception is used to pass validation messages from PasswordValidator
                        $this->sendRegisterForm($player, $e->getMessage());
                    } else {
                        $this->sendRegisterForm($player, (string)($messages["unexpected_error"] ?? "§cAn unexpected error occurred. Please try again."));
                        $this->plugin->getLogger()->error("An unexpected error occurred during form registration: " . $e->getMessage());
                    }
                }
            );
        });

        $form->setTitle((string)($registerFormConfig["title"] ?? "Register"));
        $content = (string)($registerFormConfig["content"] ?? "");
        if (!empty($content)) {
            $form->addLabel($content);
        }
        if ($errorMessage !== null) {
            $form->addLabel($errorMessage);
        }
        $rulesToggleEnabled = (bool)($this->configData->getNested("forms.register.rules_toggle.enabled") ?? false);
        if ($rulesToggleEnabled) {
            $rulesText = (string)($this->customMessages->getNested("forms.register.rules_text"));
            if (!empty($rulesText)) {
                $form->addLabel($rulesText);
            }
            $form->addToggle((string)($this->customMessages->getNested("forms.register.rules_toggle_label")), false, "rules_accepted");
        }
        $form->addInput((string)($registerFormConfig["password_label"] ?? "Password"), (string)($registerFormConfig["password_placeholder"] ?? ""), null, "password");
        $form->addInput((string)($registerFormConfig["confirm_password_label"] ?? "Confirm Password"), (string)($registerFormConfig["confirm_password_placeholder"] ?? ""), null, "confirm_password");
        $player->sendForm($form);
    }

    public function sendChangePasswordForm(Player $player, ?string $errorMessage = null): void {
        $messages = (array)$this->customMessages->get("messages");
        $formsConfig = (array)$this->customMessages->get("forms");
        $changePasswordFormConfig = (array)($formsConfig["changepassword"] ?? []);

        $form = new CustomForm(function (Player $player, ?array $data) use ($messages): void {
            if ($data === null) {
                return;
            }

            $oldPassword = (string)($data["old_password"] ?? '');
            $newPassword = (string)($data["new_password"] ?? '');
            $confirmNewPassword = (string)($data["confirm_new_password"] ?? '');

            Await::g2c(
                $this->authenticationService->handleChangePasswordRequest($player, $oldPassword, $newPassword, $confirmNewPassword),
                function () use ($player, $messages): void {
                    $player->sendMessage((string)($messages["change_password_success"] ?? "§aYour password has been changed successfully."));
                },
                function (Throwable $e) use ($player, $messages): void {
                    if ($e instanceof IncorrectPasswordException) {
                        $this->sendChangePasswordForm($player, (string)($messages["incorrect_password"] ?? "§cIncorrect password."));
                    } elseif ($e instanceof PasswordMismatchException) {
                        $this->sendChangePasswordForm($player, (string)($messages["password_mismatch"] ?? "§cPasswords do not match."));
                    } elseif ($e instanceof InvalidCommandSyntaxException) {
                        $this->sendChangePasswordForm($player, $e->getMessage());
                    } elseif ($e instanceof NotRegisteredException) {
                        $this->sendChangePasswordForm($player, (string)($messages["not_registered"] ?? "§cYou are not registered."));
                    } else {
                        $this->sendChangePasswordForm($player, (string)($messages["unexpected_error"] ?? "§cAn unexpected error occurred. Please try again."));
                        $this->plugin->getLogger()->error("An unexpected error occurred during password change form: " . $e->getMessage());
                    }
                }
            );
        });

        $form->setTitle((string)($changePasswordFormConfig["title"] ?? "Change Password"));
        $content = (string)($changePasswordFormConfig["content"] ?? "");
        if (!empty($content)) {
            $form->addLabel($content);
        }
        if ($errorMessage !== null) {
            $form->addLabel($errorMessage);
        }
        $form->addInput((string)($changePasswordFormConfig["old_password_label"] ?? "Old Password"), "", null, "old_password");
        $form->addInput((string)($changePasswordFormConfig["new_password_label"] ?? "New Password"), "", null, "new_password");
        $form->addInput((string)($changePasswordFormConfig["confirm_new_password_label"] ?? "Confirm New Password"), "", null, "confirm_new_password");
        $player->sendForm($form);
    }

    public function sendForceChangePasswordForm(Player $player, ?string $errorMessage = null): void {
        $messages = (array)$this->customMessages->get("messages");
        $formsConfig = (array)$this->customMessages->get("forms");
        $forceChangePasswordFormConfig = (array)($formsConfig["forcechangepassword"] ?? []);

        $form = new CustomForm(function (Player $player, ?array $data) use ($messages): void {
            if ($data === null) {
                if ((bool)($this->configData->getNested("forms.kick-on-close") ?? false)) {
                    $player->kick((string)($messages["force_change_password_closed"] ?? "You must change your password to continue."));
                } else {
                    $this->sendForceChangePasswordForm($player);
                }
                return;
            }

            $newPassword = (string)($data["new_password"] ?? '');
            $confirmNewPassword = (string)($data["confirm_new_password"] ?? '');

            Await::g2c(
                $this->authenticationService->handleForceChangePasswordRequest($player, $newPassword, $confirmNewPassword),
                function () use ($player, $messages): void {
                    $player->sendMessage((string)($messages["change_password_success"] ?? "§aYour password has been changed successfully."));
                },
                function (Throwable $e) use ($player, $messages): void {
                    if ($e instanceof PasswordMismatchException) {
                        $this->sendForceChangePasswordForm($player, (string)($messages["password_mismatch"] ?? "§cPasswords do not match."));
                    } elseif ($e instanceof InvalidCommandSyntaxException) {
                        $this->sendForceChangePasswordForm($player, $e->getMessage());
                    } else {
                        $this->sendForceChangePasswordForm($player, (string)($messages["unexpected_error"] ?? "§cAn unexpected error occurred. Please try again."));
                        $this->plugin->getLogger()->error("An unexpected error occurred during forced password change form: " . $e->getMessage());
                    }
                }
            );
        });

        $form->setTitle((string)($forceChangePasswordFormConfig["title"] ?? "Forced Password Change"));
        $form->addLabel((string)($messages["force_change_password_prompt"] ?? "For security reasons, you must change your password before you can continue."));
        if ($errorMessage !== null) {
            $form->addLabel($errorMessage);
        }
        $form->addInput((string)($forceChangePasswordFormConfig["new_password_label"] ?? "New Password"), "", null, "new_password");
        $form->addInput((string)($forceChangePasswordFormConfig["confirm_new_password_label"] ?? "Confirm New Password"), "", null, "confirm_new_password");
        $player->sendForm($form);
    }
}
