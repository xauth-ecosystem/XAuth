<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Auth;

use Generator;
use Luthfi\XAuth\Application\Player\PlayerStateService;
use Luthfi\XAuth\Domain\Player\VisibilityManager;
use Luthfi\XAuth\Domain\User\UserRepository;
use Luthfi\XAuth\Infrastructure\KickTaskManager;
use Luthfi\XAuth\Presentation\Title\TitleService;
use Luthfi\XAuth\Presentation\Form\FormManager;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\utils\Config;

class LogoutUser {

    private ?FormManager $formManager = null;

    public function __construct(
        private PlayerStateService $playerStateService,
        private VisibilityManager $playerVisibilityService,
        private TitleService $titleManager,
        private PluginBase $plugin,
        private KickTaskManager $kickTaskManager,
        private UserRepository $userRepository,
        private Config $customMessages,
    ) {}

    public function setFormManager(FormManager $formManager): void {
        $this->formManager = $formManager;
    }

    public function handle(Player $player): Generator {
        $this->kickTaskManager->cancel($player);
        $this->titleManager->clearTitle($player);

        $this->playerStateService->protectPlayer($player);
        $this->kickTaskManager->schedule($player);

        $playerData = yield from $this->userRepository->findByName($player->getName());
        if ($playerData !== null) {
            $formsEnabled = (bool)($this->plugin->getConfig()->getNested("forms.enabled") ?? true);
            $message = (string)(((array)$this->customMessages->get("messages"))["login_prompt"] ?? "");
            $player->sendMessage($message);
            if ($formsEnabled) {
                $this->formManager->sendLoginForm($player);
            } else {
                $this->titleManager->sendTitle($player, "login_prompt", null, true);
            }
        } else {
            $formsEnabled = (bool)($this->plugin->getConfig()->getNested("forms.enabled") ?? true);
            $message = (string)(((array)$this->customMessages->get("messages"))["register_prompt"] ?? "");
            $player->sendMessage($message);
            if ($formsEnabled) {
                $this->formManager->sendRegisterForm($player);
            } else {
                $this->titleManager->sendTitle($player, "register_prompt", null, true);
            }
        }
    }

    public function handleQuit(Player $player): void {
        $this->kickTaskManager->cancel($player);
        $this->titleManager->clearTitle($player);
        $this->playerStateService->restorePlayerState($player);
    }
}
