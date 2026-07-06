<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Player;

use Luthfi\XAuth\Domain\Event\PlayerStateSaveEvent;
use Luthfi\XAuth\PlayerState;
use pocketmine\plugin\PluginBase;
use Luthfi\XAuth\Domain\Player\VisibilityManager;
use pocketmine\entity\effect\EffectInstance;
use pocketmine\entity\effect\VanillaEffects;
use pocketmine\player\GameMode;
use pocketmine\player\Player;
use pocketmine\world\Position;

class SavePlayerState {

    /** @var array<string, PlayerState> */
    private array $protectedStates = [];

    private PluginBase $plugin;
    private VisibilityManager $visibilityService;

    public function __construct(PluginBase $plugin, VisibilityManager $visibilityService) {
        $this->plugin = $plugin;
        $this->visibilityService = $visibilityService;
    }

    public function save(Player $player): void {
        $state = new PlayerState($player, $this->plugin);
        $this->protectedStates[strtolower($player->getName())] = $state;
        (new PlayerStateSaveEvent($player, $state))->call();
    }

    public function protect(Player $player): void {
        $this->save($player);

        $config = $this->plugin->getConfig();
        $protectionConfig = (array)$config->get('protection');

        if ((bool)(($protectionConfig['force_survival'] ?? true))) {
            $player->setGamemode(GameMode::SURVIVAL());
        }

        $teleportConfig = (array)($protectionConfig['teleport'] ?? []);
        if ((bool)($teleportConfig['enabled'] ?? false)) {
            $worldName = (string)(($teleportConfig['world'] ?? $this->plugin->getServer()->getWorldManager()->getDefaultWorld()->getFolderName()));
            if ($world = $this->plugin->getServer()->getWorldManager()->getWorldByName($worldName)) {
                $coords = (array)($teleportConfig['coords'] ?? []);
                $x = (float)(($coords['x'] ?? $world->getSafeSpawn()->getX()));
                $y = (float)(($coords['y'] ?? $world->getSafeSpawn()->getY()));
                $z = (float)(($coords['z'] ?? $world->getSafeSpawn()->getZ()));
                $player->teleport(new Position($x, $y, $z, $world));
            }
        }

        if ((bool)(($protectionConfig['protect_player_state'] ?? true))) {
            $player->getInventory()->clearAll();
            $player->getArmorInventory()->clearAll();
            $player->getOffHandInventory()->clearAll();
            $player->getEffects()->clear();
            $player->setHealth($player->getMaxHealth());
            $player->getHungerManager()->setFood($player->getHungerManager()->getMaxFood());
            $player->getXpManager()->setXpLevel(0);
            $player->getXpManager()->setXpProgress(0.0);
        }

        if ((bool)$this->plugin->getConfig()->get('apply_blindness', true)) {
            $player->getEffects()->add(new EffectInstance(VanillaEffects::BLINDNESS(), 2147483647, 0, false));
        }

        $this->visibilityService->updatePlayerVisibility($player);
    }

    public function getProtectedState(Player $player): ?PlayerState {
        return $this->protectedStates[strtolower($player->getName())] ?? null;
    }

    public function removeProtectedState(Player $player): void {
        unset($this->protectedStates[strtolower($player->getName())]);
    }

    public function getAllProtectedStates(): array {
        return $this->protectedStates;
    }
}
