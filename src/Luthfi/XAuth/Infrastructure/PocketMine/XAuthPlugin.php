<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Infrastructure\PocketMine;

use Ifera\ScoreHud\ScoreHud;
use Luthfi\XAuth\Application\Auth\Pipeline\Steps\AuthenticationStep;
use Luthfi\XAuth\Infrastructure\Container;
use Luthfi\XAuth\Infrastructure\Scheduler\CleanupSessionsTask;
use Luthfi\XAuth\Presentation\Command\LoginCommand;
use Luthfi\XAuth\Presentation\Command\LogoutCommand;
use Luthfi\XAuth\Presentation\Command\RegisterCommand;
use Luthfi\XAuth\Presentation\Command\ResetPasswordCommand;
use Luthfi\XAuth\Presentation\Command\UnregisterCommand;
use Luthfi\XAuth\Presentation\Command\XAuthCommand;
use Luthfi\XAuth\Presentation\Listener\GeoIPListener;
use Luthfi\XAuth\Presentation\Listener\PlayerActionListener;
use Luthfi\XAuth\Presentation\Listener\PlayerSessionListener;
use Luthfi\XAuth\Presentation\Listener\ScoreHudListener;
use Luthfi\XAuth\Presentation\Listener\WaterdogFixListener;
use Luthfi\XAuth\Presentation\Expansion\XAuthExpansion;
use Luthfi\XAuth\Domain\Session\SessionRepository;
use Luthfi\XAuth\Domain\User\UserRepository;
use Luthfi\XAuth\Application\Auth\AuthenticationService;
use Luthfi\XAuth\Application\Player\PlayerStateService;
use Luthfi\XAuth\Infrastructure\PluginControlService;
use Luthfi\XAuth\Application\User\RegistrationService;
use Luthfi\XAuth\Application\Session\SessionService;
use Luthfi\XAuth\Domain\Auth\LoginRateLimiter;
use Luthfi\XAuth\Domain\Player\VisibilityManager;
use Luthfi\XAuth\Domain\User\PasswordHasher;
use Luthfi\XAuth\Domain\User\PasswordPolicy;
use Luthfi\XAuth\Presentation\Form\FormManager;
use Luthfi\XAuth\Presentation\Title\TitleService;
use Luthfi\XAuth\Application\Auth\Pipeline\AuthenticationFlowManager;
use pocketmine\player\Player;
use pocketmine\plugin\PluginBase;
use pocketmine\utils\Config;
use Throwable;

class XAuthPlugin extends PluginBase {

    private Container $container;

    public function onEnable(): void {
        $this->saveDefaultConfig();
        $this->saveResource("lang/en.yml");
        $this->saveResource("lang/id.yml");
        $this->saveResource("lang/ru.yml");
        $this->saveResource("lang/uk.yml");

        $this->container = new Container($this);

        try {
            $this->container->boot();
            $this->getLogger()->debug("Container booted successfully.");
        } catch (Throwable $e) {
            $this->getLogger()->error("Failed to initialize database: " . $e->getMessage());
            $this->getServer()->getPluginManager()->disablePlugin($this);
            return;
        }

        $this->checkConfigVersion();
        $this->onDatabaseInitialized();
    }

    private function checkConfigVersion(): void {
        $configData = $this->container->getConfigData();
        $currentVersion = (float)$configData->get("config-version", 1.0);
        if ($currentVersion < 1.0) {
            $this->getLogger()->warning((string)(((array)$this->container->getCustomMessages()->get("messages"))["config_outdated_warning"] ?? "Your config.yml is outdated! Please update it to the latest version."));
        }
    }

    private function onDatabaseInitialized(): void {
        $configData = $this->container->getConfigData();

        $this->container->bootFlow();

        $autoLoginEnabled = (bool)($configData->getNested("auto-login.enabled") ?? false);
        if ($autoLoginEnabled) {
            $cleanupInterval = (int)($configData->getNested("auto-login.cleanup_interval_minutes") ?? 60);
            $this->getScheduler()->scheduleRepeatingTask(new CleanupSessionsTask($this), $cleanupInterval * 20 * 60);
            $this->getLogger()->debug("Expired session cleanup task scheduled.");
        }

        $this->getServer()->getPluginManager()->registerEvents(new PlayerActionListener($this), $this);
        $this->getServer()->getPluginManager()->registerEvents(new PlayerSessionListener($this), $this);

        if ((bool)($configData->getNested("waterdog-fix.enabled") ?? false)) {
            if ($this->getServer()->getConfigGroup()->getPropertyBool("player.verify-xuid", true)) {
                $this->getLogger()->warning("XAuth's WaterdogPE fix may not work correctly. To prevent issues, set 'player.verify-xuid' in pocketmine.yml to 'false'");
            }
            if ($this->getServer()->getOnlineMode()) {
                $this->getLogger()->alert("XAuth's WaterdogPE fix is not compatible with online mode. Please set 'xbox-auth' in server.properties to 'off'");
            }
            $this->getServer()->getPluginManager()->registerEvents(new WaterdogFixListener($this), $this);
            $this->getLogger()->info("WaterdogPE fix enabled!");
        }

        if ((bool)(($configData->getNested("geoip.enabled") ?? false))) {
            $this->getServer()->getPluginManager()->registerEvents(new GeoIPListener($this), $this);
        }

        $scoreHudPlugin = $this->getServer()->getPluginManager()->getPlugin("ScoreHud");
        if ($scoreHudPlugin instanceof ScoreHud) {
            $this->getServer()->getPluginManager()->registerEvents(new ScoreHudListener($this), $this);
        }

        $placeholderAPI = $this->getServer()->getPluginManager()->getPlugin("PlaceholderAPI");
        if ($placeholderAPI instanceof \MohamadRZ4\Placeholder\PlaceholderAPI) {
            $placeholderAPI->registerExpansion(new XAuthExpansion($this));
        }

        $this->getServer()->getCommandMap()->register("register", new RegisterCommand($this));
        $this->getServer()->getCommandMap()->register("login", new LoginCommand($this));
        $this->getServer()->getCommandMap()->register("resetpassword", new ResetPasswordCommand($this));
        $this->getServer()->getCommandMap()->register("logout", new LogoutCommand($this));
        $this->getServer()->getCommandMap()->register("unregister", new UnregisterCommand($this));
        $this->getServer()->getCommandMap()->register("xauth", new XAuthCommand($this));
    }

    public function getContainer(): Container {
        return $this->container;
    }

    // Delegation methods for backward compatibility

    public function getUserRepository(): ?UserRepository {
        return $this->container->getUserRepository();
    }

    public function getSessionRepository(): ?SessionRepository {
        return $this->container->getSessionRepository();
    }

    public function getCustomMessages(): Config {
        return $this->container->getCustomMessages();
    }

    public function getPasswordPolicy(): PasswordPolicy {
        return $this->container->getPasswordPolicy();
    }

    public function getPasswordHasher(): PasswordHasher {
        return $this->container->getPasswordHasher();
    }

    public function getFormManager(): FormManager {
        return $this->container->getFormManager();
    }

    public function getAuthenticationService(): AuthenticationService {
        return $this->container->getAuthenticationService();
    }

    public function getRegistrationService(): RegistrationService {
        return $this->container->getRegistrationService();
    }

    public function getSessionService(): SessionService {
        return $this->container->getSessionService();
    }

    public function getPlayerStateService(): PlayerStateService {
        return $this->container->getPlayerStateService();
    }

    public function getVisibilityManager(): VisibilityManager {
        return $this->container->getVisibilityManager();
    }

    public function getPluginControlService(): PluginControlService {
        return $this->container->getPluginControlService();
    }

    public function getMigrationManager(): \Luthfi\XAuth\Infrastructure\MigrationManager {
        return $this->container->getMigrationManager();
    }

    public function getAuthenticationFlowManager(): AuthenticationFlowManager {
        return $this->container->getAuthenticationFlowManager();
    }

    public function getTitleService(): TitleService {
        return $this->container->getTitleService();
    }

    public function getLoginRateLimiter(): LoginRateLimiter {
        return $this->container->getLoginRateLimiter();
    }

    public function registerAuthenticationStep(AuthenticationStep $step): void {
        $this->container->registerAuthenticationStep($step);
    }

    public function startAuthenticationStep(Player $player, ?string $startStepId = null): void {
        $this->container->startAuthenticationStep($player, $startStepId);
    }

    public function completeAuthenticationStep(Player $player, string $completedStepId): void {
        $this->container->completeAuthenticationStep($player, $completedStepId);
    }

    public function getPlayerAuthenticationStepStatus(Player $player, string $stepId): ?string {
        return $this->container->getPlayerAuthenticationStepStatus($player, $stepId);
    }

    /** @return array<string, AuthenticationStep> */
    public function getAuthenticationSteps(): array {
        return $this->container->getAuthenticationSteps();
    }

    public function getOrderedAuthenticationSteps(): array {
        return $this->container->getOrderedAuthenticationSteps();
    }

    public function cancelKickTask(Player $player): void {
        $this->container->cancelKickTask($player);
    }

    public function scheduleKickTask(Player $player): void {
        $this->container->scheduleKickTask($player);
    }

    /** @return array<string, string> */
    public function &getDeviceIds(): array {
        return $this->container->getDeviceIds();
    }

    public function onDisable(): void {
        $this->container->close();
    }
}
