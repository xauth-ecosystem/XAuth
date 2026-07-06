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

namespace Luthfi\XAuth\Presentation\Listener;

use Luthfi\XAuth\Infrastructure\Network\Handler\WaterdogExtrasLoginPacketHandler;
use pocketmine\event\Listener;
use pocketmine\event\server\DataPacketReceiveEvent;
use pocketmine\network\mcpe\JwtException;
use pocketmine\network\mcpe\JwtUtils;
use pocketmine\network\mcpe\protocol\LoginPacket;
use pocketmine\network\PacketHandlingException;
use pocketmine\plugin\PluginBase;
use pocketmine\Server;
use ChernegaSergiy\Language\TranslatorInterface;
use pocketmine\utils\TextFormat;
use Throwable;

class WaterdogFixListener implements Listener {

    public function __construct(
        private PluginBase $plugin,
        private TranslatorInterface $translator,
    ) {}

    /**
     * @param DataPacketReceiveEvent $event
     * @priority MONITOR
     * @handleCancelled true
     */
    public function onDataPacketReceive(DataPacketReceiveEvent $event): void {
        $packet = $event->getPacket();
        if ($packet instanceof LoginPacket) {
            try {
                [, $clientData,] = JwtUtils::parse($packet->clientDataJwt);
            } catch (JwtException $e) {
                throw PacketHandlingException::wrap($e);
            }

            $config = $this->plugin->getConfig();
            $forceWaterdog = (bool)($config->getNested("waterdog-fix.force-players-to-waterdog") ?? false);
            $waterdogBindAddress = (string)($config->getNested("waterdog-fix.waterdog-bind-address") ?? "127.0.0.1");

            if (
                (
                    !isset($clientData["Waterdog_XUID"])
                    || !isset($clientData["Waterdog_IP"])
                    || !$this->checkIpAddress($event->getOrigin()->getIp(), $waterdogBindAddress)
                )
                && $forceWaterdog
            ) {
                $kickMessage = $this->translator->translate($this->translator->getDefaultLocale(), "messages.waterdog_kick_message", [], null);
                $event->getOrigin()->disconnect($kickMessage);
                return;
            }

            if (isset($clientData["Waterdog_IP"])) {
                $event->getOrigin()->setHandler(new WaterdogExtrasLoginPacketHandler(
                    Server::getInstance(),
                    $event->getOrigin(),
                    $clientData["Waterdog_XUID"],
                    $clientData["Waterdog_IP"],
                    $this->translator
                ));
            }
            unset($clientData);
        }
    }

    private function checkIpAddress(string $providedIpAddress, string $waterdogBindAddress): bool {
        if (!filter_var($providedIpAddress, FILTER_VALIDATE_IP)) {
            $providedIpAddress = gethostbyname($providedIpAddress);
        }
        if (strtolower($providedIpAddress) === "localhost" || $providedIpAddress === "0.0.0.0") {
            $providedIpAddress = "127.0.0.1";
        }
        return $providedIpAddress == $waterdogBindAddress;
    }
}
