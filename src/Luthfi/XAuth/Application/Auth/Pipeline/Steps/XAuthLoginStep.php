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

namespace Luthfi\XAuth\Application\Auth\Pipeline\Steps;

use Luthfi\XAuth\Application\Auth\AuthenticationFacade;
use Luthfi\XAuth\Application\Auth\Pipeline\AuthenticationContext;
use Luthfi\XAuth\Application\Auth\Pipeline\Steps\AuthenticationStep;
use Luthfi\XAuth\Application\Player\PlayerStateFacade;
use Luthfi\XAuth\Domain\User\UserRepository;
use Luthfi\XAuth\Infrastructure\KickTaskManager;
use Luthfi\XAuth\Presentation\Form\FormManager;
use Luthfi\XAuth\Presentation\Title\TitleService;
use Luthfi\XAuth\Domain\Event\PlayerAuthenticateEvent;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\utils\Config;
use SOFe\AwaitGenerator\Await;

class XAuthLoginStep implements AuthenticationStep, FinalizableStep {

    public function __construct(
        private PluginBase $plugin,
        private Config $configData,
        private Config $customMessages,
        private FormManager $formManager,
        private TitleService $titleService,
        private AuthenticationFacade $authenticationService,
        private PlayerStateFacade $playerStateService,
        private AuthenticationFlowManager $authenticationFlowManager,
        private ?UserRepository $userRepository,
        private KickTaskManager $kickTaskManager,
    ) {
    }

    public function getId(): string {
        return 'xauth_login';
    }

    public function start(Player $player): void {
        Await::f2c(function () use ($player) {
            if ($this->authenticationService->isPlayerAuthenticated($player)) {
                $this->skip($player);
                return;
            }

            $playerData = yield from $this->userRepository->findByName($player->getName());
            if ($playerData !== null) {
                $this->playerStateService->protectPlayer($player);
                $this->kickTaskManager->schedule($player);
                $formsEnabled = $this->configData->getNested("forms.enabled", true);
                $message = (string)(((array)$this->customMessages->get("messages"))["login_prompt"] ?? "");
                $player->sendMessage($message);
                if ($formsEnabled) {
                    $this->formManager->sendLoginForm($player);
                } else {
                    $this->titleService->sendTitle($player, "login_prompt", null, true);
                }
            } else {
                $this->skip($player); 
            }
        });
    }

    public function complete(Player $player): void {
        $this->authenticationFlowManager->completeStep($player, $this->getId());
    }

    public function skip(Player $player): void {
        $this->authenticationFlowManager->skipStep($player, $this->getId());
    }

    public function onFlowComplete(Player $player, AuthenticationContext $context): void {
        if ($context->wasStepCompleted($this->getId())) {
            $messages = (array)$this->customMessages->get("messages");
            $player->sendMessage((string)($messages["login_success"] ?? ""));
            $this->titleService->sendTitle($player, "login_success", 2 * 20);
        }
    }
}
