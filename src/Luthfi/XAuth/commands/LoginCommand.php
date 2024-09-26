<?php

namespace Luthfi\XAuth\commands;

use pocketmine\command\Command;
use pocketmine\command\CommandSender;
use pocketmine\player\Player;
use Luthfi\XAuth\Main;

class LoginCommand extends Command {

    private Main $plugin;

    public function __construct(Main $plugin) {
        parent::__construct("login", "Login to your account", "/login <password>");
        $this->plugin = $plugin;
    }

    public function execute(CommandSender $sender, string $label, array $args): bool {
        if (!$sender instanceof Player) {
            $sender->sendMessage("This command can only be used in-game.");
            return false;
        }

        $name = strtolower($sender->getName());
        if (count($args) !== 1) {
            $sender->sendMessage($this->plugin->getCustomMessages()->get("login_usage"));
            return false;
        }

        if (!$this->plugin->getPlayerData()->exists($name)) {
            $sender->sendMessage($this->plugin->getCustomMessages()->get("not_registered"));
            return false;
        }

        $password = $args[0];
        $storedPassword = $this->plugin->getPlayerData()->get($name)["password"];

        if ($password !== $storedPassword) {
            $sender->sendMessage($this->plugin->getCustomMessages()->get("incorrect_password"));
            return false;
        }

        $sender->sendMessage($this->plugin->getCustomMessages()->get("login_success"));
        return true;
    }
}
