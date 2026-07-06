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

namespace Luthfi\XAuth\Infrastructure;

use Luthfi\XAuth\Domain\Player\VisibilityManager;
use pocketmine\plugin\PluginBase;
use pocketmine\utils\Config;

class PluginControlService {

    public function __construct(
        private PluginBase $plugin,
        private Config $customMessages,
        private VisibilityManager $visibilityManager,
    ) {}

    public function reload(): void {
        $config = $this->plugin->getConfig();

        $oldData = [
            'in_world_visibility' => (array)$config->get('in_world_visibility', []),
            'player_list_visibility' => (array)$config->get('player_list_visibility', []),
            'apply_blindness' => (bool)$config->get('apply_blindness', true)
        ];

        $config->reload();
        $this->customMessages->reload();

        $newData = [
            'in_world_visibility' => (array)$config->get('in_world_visibility', []),
            'player_list_visibility' => (array)$config->get('player_list_visibility', []),
            'apply_blindness' => (bool)$config->get('apply_blindness', true)
        ];

        if ($oldData !== $newData) {
            foreach ($this->plugin->getServer()->getOnlinePlayers() as $player) {
                $this->visibilityManager->updatePlayerVisibility($player);
            }
        }
    }
}
