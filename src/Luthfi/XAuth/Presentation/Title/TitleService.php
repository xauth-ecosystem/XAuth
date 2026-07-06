<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Presentation\Title;

use Luthfi\XAuth\Infrastructure\Scheduler\SendTitleTask;
use ChernegaSergiy\Language\TranslatorInterface;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\scheduler\TaskHandler;

class TitleService 
{
    /** @var array<string, TaskHandler> */
    private array $titleTasks = [];

    public function __construct(
        private PluginBase $plugin,
        private TranslatorInterface $translator,
    ) {}

    public function sendTitle(Player $player, string $messageKey, ?int $duration = null, bool $isRepeating = false): void
    {
        $this->clearTitle($player);

        $configData = $this->plugin->getConfig();
        if (!(bool)$configData->get("enable_titles", false)) {
            return;
        }

        $titleKey = "titles." . $messageKey . ".title";
        $subtitleKey = "titles." . $messageKey . ".subtitle";
        $intervalKey = "titles." . $messageKey . ".interval";

        $title = $this->translator->translateFor($player, $titleKey);
        $subtitle = $this->translator->translateFor($player, $subtitleKey);

        if ($title === $titleKey && $subtitle === $subtitleKey) {
            return;
        }

        $interval = (int)($this->translator->translateFor($player, $intervalKey));

        if ($isRepeating) {
            $taskInterval = $interval * 20;
            $handler = $this->plugin->getScheduler()->scheduleRepeatingTask(new SendTitleTask($this->plugin, $player, $title, $subtitle), $taskInterval);
            $this->titleTasks[$player->getName()] = $handler;
        } else {
            $stay = $duration ?? ($interval * 20);
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
