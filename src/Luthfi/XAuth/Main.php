<?php

declare(strict_types=1);

namespace Luthfi\XAuth;

use Luthfi\XAuth\Infrastructure\Container;
use pocketmine\plugin\PluginBase;
use Throwable;

class Main extends PluginBase {

    private Container $container;

    public function onEnable(): void {
        $this->container = new Container($this);

        try {
            $this->container->boot();
            $this->container->registerFramework();
        } catch (Throwable $e) {
            $this->getLogger()->error("Failed to initialize: " . $e->getMessage());
            $this->getServer()->getPluginManager()->disablePlugin($this);
        }
    }

    public function onDisable(): void {
        $this->container?->close();
    }

    public function getContainer(): Container {
        return $this->container;
    }
}
