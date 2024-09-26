<?php

namespace Luthfi\XAuth\commands;

use pocketmine\command\Command;
use pocketmine\command\CommandSender;
use pocketmine\player\Player;
use Luthfi\XAuth\Main;

class ResetPasswordCommand extends Command {

    private Main $plugin;

    public function __construct(Main $plugin) {
        parent::__construct("resetpassword", "Reset your password", "/resetpassword <oldpassword> <newpassword>");
        $this->plugin = $plugin;
    }

    public function execute(CommandSender $sender, string $label, array $args): bool {
        if (!$sender instanceof Player) {
            $sender->sendMessage("This command can only be used in-game.");
            return false;
        }

        $name = strtolower($sender->getName());
        if (count($args) !== 2) {
            $sender->sendMessage($this->plugin->getCustomMessages()->get("reset_usage"));
            return false;
        }

        if (!$this->plugin->getPlayerData()->exists($name)) {
            $sender->sendMessage($this->plugin->getCustomMessages()->get("not_registered"));
            return false;
        }

        $oldPassword = $args[0];
        $newPassword = $args[1];
        $storedPassword = $this->plugin->getPlayerData()->get($name)["password"];

        if ($oldPassword !== $storedPassword) {
            $sender->sendMessage($this->plugin->getCustomMessages()->get("incorrect_password"));
            return false;
        }

        $this->plugin->getPlayerData()->set($name, [
            "password" => $newPassword,
            "ip" => $this->plugin->getPlayerData()->get($name)["ip"]
        ]);
        $this->plugin->getPlayerData()->save();

        $sender->sendMessage($this->plugin->getCustomMessages()->get("reset_success"));
        return true;
    }
}
