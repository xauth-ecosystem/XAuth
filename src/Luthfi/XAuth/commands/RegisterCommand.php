<?php

namespace Luthfi\XAuth\commands;

use pocketmine\command\Command;
use pocketmine\command\CommandSender;
use pocketmine\player\Player;
use Luthfi\XAuth\Main;

class RegisterCommand extends Command {

    private Main $plugin;

    public function __construct(Main $plugin) {
        parent::__construct("register", "Register your account", "/register <password> <confirmpassword>");
        $this->plugin = $plugin;
    }

    public function execute(CommandSender $sender, string $label, array $args): bool {
        if (!$sender instanceof Player) {
            $sender->sendMessage("This command can only be used in-game.");
            return false;
        }

        $name = strtolower($sender->getName());
        if (count($args) !== 2) {
            $sender->sendMessage($this->plugin->getCustomMessages()->get("register_usage"));
            return false;
        }

        if ($this->plugin->getPlayerData()->exists($name)) {
            $sender->sendMessage($this->plugin->getCustomMessages()->get("already_registered"));
            return false;
        }

        $password = $args[0];
        $confirmPassword = $args[1];

        if ($password !== $confirmPassword) {
            $sender->sendMessage($this->plugin->getCustomMessages()->get("password_mismatch"));
            return false;
        }

        $this->plugin->getPlayerData()->set($name, [
            "password" => $password,
            "ip" => $sender->getNetworkSession()->getIp()
        ]);
        $this->plugin->getPlayerData()->save();

        $sender->sendMessage($this->plugin->getCustomMessages()->get("register_success"));
        return true;
    }
}
