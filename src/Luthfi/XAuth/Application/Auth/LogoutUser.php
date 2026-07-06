<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Auth;

use Generator;
use Luthfi\XAuth\event\PlayerDeauthenticateEvent;
use Luthfi\XAuth\repository\UserRepository;
use Luthfi\XAuth\service\PlayerStateService;
use Luthfi\XAuth\service\PlayerVisibilityService;
use Luthfi\XAuth\TitleManager;
use Luthfi\XAuth\FormManager;
use pocketmine\player\Player;

class LogoutUser {

    public function __construct(
        private LoginUser $loginUser,
        private PlayerStateService $playerStateService,
        private PlayerVisibilityService $playerVisibilityService,
        private TitleManager $titleManager,
        private FormManager $formManager,
        private \Luthfi\XAuth\Main $plugin,
    ) {}

    public function handle(Player $player): Generator {
        $this->plugin->cancelKickTask($player);
        $this->titleManager->clearTitle($player);

        $this->loginUser->deauthenticate($player);

        $this->playerStateService->protectPlayer($player);
        $this->plugin->scheduleKickTask($player);

        $playerData = yield from $this->plugin->getUserRepository()->findByName($player->getName());
        if ($playerData !== null) {
            $formsEnabled = (bool)($this->plugin->getConfig()->getNested("forms.enabled") ?? true);
            $message = (string)(((array)$this->plugin->getCustomMessages()->get("messages"))["login_prompt"] ?? "");
            $player->sendMessage($message);
            if ($formsEnabled) {
                $this->formManager->sendLoginForm($player);
            } else {
                $this->titleManager->sendTitle($player, "login_prompt", null, true);
            }
        } else {
            $formsEnabled = (bool)($this->plugin->getConfig()->getNested("forms.enabled") ?? true);
            $message = (string)(((array)$this->plugin->getCustomMessages()->get("messages"))["register_prompt"] ?? "");
            $player->sendMessage($message);
            if ($formsEnabled) {
                $this->formManager->sendRegisterForm($player);
            } else {
                $this->titleManager->sendTitle($player, "register_prompt", null, true);
            }
        }

        (new PlayerDeauthenticateEvent($player, false))->call();
    }

    public function handleQuit(Player $player): void {
        $this->plugin->cancelKickTask($player);
        $this->titleManager->clearTitle($player);

        $this->loginUser->deauthenticate($player);

        $this->playerStateService->restorePlayerState($player);

        (new PlayerDeauthenticateEvent($player, true))->call();
    }
}
