<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Player;

use Luthfi\XAuth\event\PlayerStateRestoreEvent;
use pocketmine\player\Player;

class RestorePlayerState {

    public function __construct(
        private SavePlayerState $savePlayerState,
    ) {}

    public function restore(Player $player): void {
        $name = strtolower($player->getName());
        $protectedStates = $this->savePlayerState->getAllProtectedStates();
        if (isset($protectedStates[$name])) {
            $event = new PlayerStateRestoreEvent($player, $protectedStates[$name]);
            $event->call();
            if ($event->isCancelled()) {
                $this->savePlayerState->removeProtectedState($player);
                return;
            }
            $protectedStates[$name]->restore($player);
            $this->savePlayerState->removeProtectedState($player);
        }
    }
}
