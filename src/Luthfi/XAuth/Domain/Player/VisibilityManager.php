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

namespace Luthfi\XAuth\Domain\Player;

use Closure;
use pocketmine\entity\effect\EffectInstance;
use pocketmine\entity\effect\VanillaEffects;
use pocketmine\network\mcpe\NetworkBroadcastUtils;
use pocketmine\network\mcpe\protocol\PlayerListPacket;
use pocketmine\network\mcpe\protocol\types\PlayerListEntry;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\utils\Config;

class VisibilityManager {

    public function __construct(
        private PluginBase $plugin,
        private Config $configData,
        private Config $customMessages,
    ) {}

    public function updatePlayerVisibility(Player $targetPlayer, Closure $isAuthenticated): void {
        foreach ($this->plugin->getServer()->getOnlinePlayers() as $otherPlayer) {
            if ($targetPlayer === $otherPlayer) continue;

            $this->resolveVisibility($otherPlayer, $targetPlayer, $isAuthenticated($otherPlayer), $isAuthenticated($targetPlayer));
        }
    }

    private function resolveVisibility(Player $observer, Player $subject, bool $observerAuthenticated, bool $subjectAuthenticated): void {
        $config = $this->configData;

        if ($observerAuthenticated) {
            $inWorldMode = strtolower((string)($config->getNested('in_world_visibility.mode') ?? 'packets'));
            if ($subjectAuthenticated) {
                $observer->showPlayer($subject);
                if ($inWorldMode === 'effect') {
                    $subject->getEffects()->remove(VanillaEffects::INVISIBILITY());
                }
            } else {
                if ($inWorldMode === 'packets') {
                    $observer->hidePlayer($subject);
                } elseif ($inWorldMode === 'effect') {
                    $subject->getEffects()->add(new EffectInstance(VanillaEffects::INVISIBILITY(), 2147483647, 0, false));
                } else {
                    $observer->showPlayer($subject);
                    $subject->getEffects()->remove(VanillaEffects::INVISIBILITY());
                }
            }

            if (!$subjectAuthenticated && (bool)$config->getNested('player_list_visibility.hide', true)) {
                $this->hideFromPlayerList($observer, $subject);
            } else {
                $this->showInPlayerList($observer, $subject);
            }
        } else {
            if ($config->getNested('in_world_visibility.hide_others_from_unauthenticated', true)) {
                $observer->hidePlayer($subject);
            } else {
                $observer->showPlayer($subject);
            }

            if ($config->getNested('player_list_visibility.hide_others_from_unauthenticated', false)) {
                $this->hideFromPlayerList($observer, $subject);
            } else {
                $this->showInPlayerList($observer, $subject);
            }
        }
    }

    private function hideFromPlayerList(Player $observer, Player $subject): void {
        NetworkBroadcastUtils::broadcastPackets(
            [$observer],
            [PlayerListPacket::remove([
                PlayerListEntry::createRemovalEntry($subject->getUniqueId())
            ])]
        );
    }

    private function showInPlayerList(Player $observer, Player $subject): void {
        $networkSession = $subject->getNetworkSession();
        if (!$networkSession->isConnected()) {
            return;
        }

        $typeConverter = $networkSession->getTypeConverter();
        $skinData = $typeConverter->getSkinAdapter()->toSkinData($subject->getSkin());

        NetworkBroadcastUtils::broadcastPackets(
            [$observer],
            [PlayerListPacket::add([
                PlayerListEntry::createAdditionEntry(
                    $subject->getUniqueId(),
                    $subject->getId(),
                    $subject->getName(),
                    $skinData
                )
            ])]
        );
    }
}
