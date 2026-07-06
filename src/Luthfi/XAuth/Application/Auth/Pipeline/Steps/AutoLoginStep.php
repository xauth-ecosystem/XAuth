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

use Luthfi\XAuth\Application\Auth\Pipeline\AuthenticationFlowManager;
use Luthfi\XAuth\Application\Auth\Pipeline\AuthenticationContext;
use Luthfi\XAuth\Domain\Session\SessionRepository;
use Luthfi\XAuth\Infrastructure\DeviceIdStore;
use Luthfi\XAuth\Presentation\Title\TitleService;
use Luthfi\XAuth\Domain\Event\PlayerPreAuthenticateEvent;
use ChernegaSergiy\Language\TranslatorInterface;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\utils\Config;
use SOFe\AwaitGenerator\Await;

class AutoLoginStep implements AuthenticationStep, FinalizableStep {

    public function __construct(
        private PluginBase $plugin,
        private Config $configData,
        private TranslatorInterface $translator,
        private TitleService $titleService,
        private AuthenticationFlowManager $authenticationFlowManager,
        private ?SessionRepository $sessionRepository,
        private DeviceIdStore $deviceIdStore,
    ) {
    }

    public function getId(): string {
        return 'auto_login';
    }

    public function start(Player $player): void {
        $playerName = $player->getName();
        $autoLoginConfig = (array)$this->configData->get("auto-login", []);

        if ((bool)($autoLoginConfig["enabled"] ?? false)) {
            Await::f2c(function() use ($player, $playerName, $autoLoginConfig) {
                $sessions = yield from $this->sessionRepository->findAllByPlayer($playerName);
                $ip = $player->getNetworkSession()->getIp();
                $securityLevel = (int)($autoLoginConfig["security_level"] ?? 1);

                foreach ($sessions as $sessionData) {
                    if ($sessionData->isExpired()) {
                        continue;
                    }

                    $ipMatch = $sessionData->getIpAddress() === $ip;
                    $deviceId = $this->deviceIdStore->get(strtolower($playerName)) ?? null;
                    $deviceIdMatch = $sessionData->getDeviceId()->value() === $deviceId;

                    if (($securityLevel === 1 && $ipMatch && $deviceIdMatch) || ($securityLevel === 0 && $ipMatch)) {
                        $this->authenticationFlowManager->getContextForPlayer($player)->setLoginType(PlayerPreAuthenticateEvent::LOGIN_TYPE_AUTO);
                        $this->complete($player);
                        return;
                    }
                }

                $this->skip($player);
            });
            return;
        }

        $this->skip($player);
    }

    public function complete(Player $player): void {
        $this->authenticationFlowManager->completeStep($player, $this->getId());
    }

    public function skip(Player $player): void {
        $this->authenticationFlowManager->skipStep($player, $this->getId());
    }

    public function onFlowComplete(Player $player, AuthenticationContext $context): void {
        if ($context->wasStepCompleted($this->getId())) {
            $player->sendMessage($this->translator->translateFor($player, "messages.auto_login_success"));
            $this->titleService->sendTitle($player, "auto_login_success", 2 * 20);
        }
    }
}
