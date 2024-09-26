<?php

namespace Luthfi\XAuth;

use pocketmine\plugin\PluginBase;
use pocketmine\event\Listener;
use pocketmine\event\player\PlayerJoinEvent;
use pocketmine\event\player\PlayerQuitEvent;
use pocketmine\player\Player;
use pocketmine\utils\Config;
use Luthfi\XAuth\commands\RegisterCommand;
use Luthfi\XAuth\commands\LoginCommand;
use Luthfi\XAuth\commands\ResetPasswordCommand;

class Main extends PluginBase implements Listener {

    private Config $playerData;
    private Config $configData;

    public function onEnable(): void {
        $this->getServer()->getPluginManager()->registerEvents($this, $this);
        $this->playerData = new Config($this->getDataFolder() . "players.yml", Config::YAML);
        $this->saveDefaultConfig();
        $this->configData = $this->getConfig();
        $this->getServer()->getCommandMap()->register("register", new RegisterCommand($this));
        $this->getServer()->getCommandMap()->register("login", new LoginCommand($this));
        $this->getServer()->getCommandMap()->register("resetpassword", new ResetPasswordCommand($this));
    }

    public function onJoin(PlayerJoinEvent $event): void {
        $player = $event->getPlayer();
        $name = strtolower($player->getName());

        if ($this->playerData->exists($name)) {
            $ip = $this->playerData->get($name)["ip"];
            $currentIp = $player->getNetworkSession()->getIp();

            if ($this->configData->get("auto-login") && $ip === $currentIp) {
                $player->sendMessage($this->configData->get("login_success"));
                $this->sendTitleMessage($player, "login_success");
            } else {
                $player->sendMessage($this->configData->get("login_prompt"));
                $this->sendTitleMessage($player, "login_prompt");
            }
        } else {
            $player->sendMessage($this->configData->get("register_prompt"));
            $this->sendTitleMessage($player, "register_prompt");
        }
    }

    private function sendTitleMessage(Player $player, string $messageKey): void {
        if ($this->configData->get("enable_titles")) {
            $titleConfig = $this->configData->get("titles")[$messageKey];
            $title = $titleConfig["title"];
            $subtitle = $titleConfig["subtitle"];
            $interval = $titleConfig["interval"] * 20;

            $this->getScheduler()->scheduleRepeatingTask(new class($player, $title, $subtitle) extends \pocketmine\scheduler\Task {
                private Player $player;
                private string $title;
                private string $subtitle;

                public function __construct(Player $player, string $title, string $subtitle) {
                    $this->player = $player;
                    $this->title = $title;
                    $this->subtitle = $subtitle;
                }

                public function onRun(): void {
                    if ($this->player->isOnline()) {
                        $this->player->sendTitle($this->title, $this->subtitle);
                    }
                }
            }, $interval);
        }
    }

    public function getPlayerData(): Config {
        return $this->playerData;
    }

    public function getCustomMessages(): Config {
        return $this->configData;
    }
}
