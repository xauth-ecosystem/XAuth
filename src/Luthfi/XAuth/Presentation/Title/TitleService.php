<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Presentation\Title;

use Luthfi\XAuth\Infrastructure\Scheduler\SendTitleTask;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\scheduler\TaskHandler;
use pocketmine\utils\Config;

class TitleService 
{
    /** @var array<string, TaskHandler> */
    private array $titleTasks = [];

    public function __construct(
        private PluginBase $plugin,
        private Config $configData,
        private Config $customMessages,
    ) {}

    public function sendTitle(Player $player, string $messageKey, ?int $duration = null, bool $isRepeating = false): void
    {
        $this->clearTitle($player);

        if (!(bool)$this->configData->get("enable_titles", false)) {
            return;
        }

        $titlesConfig = (array)$this->customMessages->get("titles", []);
        if (!isset($titlesConfig[$messageKey])) {
            return;
        }

        $titleConfig = $titlesConfig[$messageKey];
        $title = (string)($titleConfig["title"] ?? "");
        $subtitle = (string)($titleConfig["subtitle"] ?? "");
        
        if ($isRepeating) {
            $interval = (int)(($titleConfig["interval"] ?? 2) * 20);
            $handler = $this->plugin->getScheduler()->scheduleRepeatingTask(new SendTitleTask($this->plugin, $player, $title, $subtitle), $interval);
            $this->titleTasks[$player->getName()] = $handler;
        } else {
            $stay = $duration ?? (int)(($titleConfig["interval"] ?? 2) * 20);
            $player->sendTitle($title, $subtitle, 10, $stay, 10);
        }
    }

    public function clearTitle(Player $player): void
    {
        $name = $player->getName();
        if (isset($this->titleTasks[$name])) {
            $this->titleTasks[$name]->cancel();
            unset($this->titleTasks[$name]);
        }
        $player->sendTitle("", "", 0, 0, 0);
    }
}
