<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Infrastructure;

use Luthfi\XAuth\Infrastructure\Scheduler\KickTask;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\scheduler\TaskHandler;
use pocketmine\utils\Config;

class KickTaskManager {

    /** @var array<string, TaskHandler> */
    private array $kickTasks = [];

    public function __construct(
        private PluginBase $plugin,
        private Config $configData,
        private Config $customMessages,
    ) {}

    public function cancel(Player $player): void {
        $name = $player->getName();
        if (isset($this->kickTasks[$name])) {
            $this->kickTasks[$name]->cancel();
            unset($this->kickTasks[$name]);
        }
    }

    public function schedule(Player $player): void {
        $loginTimeout = (int)($this->configData->getNested("session.login-timeout") ?? 30);
        if ($loginTimeout > 0) {
            $this->kickTasks[$player->getName()] = $this->plugin->getScheduler()->scheduleDelayedTask(
                new KickTask($player, $this->customMessages),
                $loginTimeout * 20
            );
        }
    }
}
