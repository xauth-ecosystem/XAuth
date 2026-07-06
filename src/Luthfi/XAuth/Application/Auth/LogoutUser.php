<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Auth;

use Generator;
use Luthfi\XAuth\Application\Player\PlayerStateFacade;
use Luthfi\XAuth\Infrastructure\VisibilityManager;
use Luthfi\XAuth\Domain\User\UserRepository;
use Luthfi\XAuth\Infrastructure\KickTaskManager;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;

class LogoutUser {

    public function __construct(
        private PlayerStateFacade $playerStateService,
        private VisibilityManager $playerVisibilityService,
        private PluginBase $plugin,
        private KickTaskManager $kickTaskManager,
        private UserRepository $userRepository,
    ) {}

    public function handle(Player $player): Generator {
        $this->kickTaskManager->cancel($player);

        $this->playerStateService->protectPlayer($player);
        $this->kickTaskManager->schedule($player);

        $playerData = yield from $this->userRepository->findByName($player->getName());
        return $playerData !== null ? LogoutOutcome::EXISTING_USER : LogoutOutcome::NEW_USER;
    }

    public function handleQuit(Player $player): void {
        $this->kickTaskManager->cancel($player);
        $this->playerStateService->restorePlayerState($player);
    }
}
