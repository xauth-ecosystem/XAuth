<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Infrastructure;

use Luthfi\XAuth\Application\Auth\ChangePassword;
use Luthfi\XAuth\Application\Auth\LoginUser;
use Luthfi\XAuth\Application\Auth\LogoutUser;
use Luthfi\XAuth\Application\Auth\VerifyPassword;
use Luthfi\XAuth\Application\Session\CreateSession;
use Luthfi\XAuth\Application\Session\RestoreSession;
use Luthfi\XAuth\Application\Session\TerminateSession;
use Luthfi\XAuth\Application\User\RegisterUser;
use Luthfi\XAuth\Application\User\DeleteUser;
use Luthfi\XAuth\Domain\Auth\LoginRateLimiter;
use Luthfi\XAuth\Domain\Player\VisibilityManager;
use Luthfi\XAuth\Domain\User\PasswordHasher;
use Luthfi\XAuth\Domain\User\PasswordPolicy;
use Luthfi\XAuth\Infrastructure\Persistence\DatabaseManager;
use Luthfi\XAuth\Infrastructure\Scheduler\KickTask;
use Luthfi\XAuth\Presentation\Form\FormManager;
use Luthfi\XAuth\Presentation\Title\TitleService;
use Luthfi\XAuth\Domain\Session\SessionRepository;
use Luthfi\XAuth\Domain\User\UserRepository;
use Luthfi\XAuth\Application\Auth\AuthenticationService;
use Luthfi\XAuth\Application\Player\PlayerStateService;
use Luthfi\XAuth\Infrastructure\PluginControlService;
use Luthfi\XAuth\Application\User\RegistrationService;
use Luthfi\XAuth\Application\Session\SessionService;
use Luthfi\XAuth\Application\Auth\Pipeline\AuthenticationFlowManager;
use Luthfi\XAuth\Application\Auth\Pipeline\Steps\AuthenticationStep;
use pocketmine\player\Player;
use pocketmine\scheduler\TaskHandler;
use pocketmine\utils\Config;

class Container {

    private DatabaseManager $databaseManager;
    private Config $configData;
    private Config $languageMessages;
    private FormManager $formManager;
    private PasswordPolicy $passwordPolicy;
    private PasswordHasher $passwordHasher;
    private AuthenticationService $authenticationService;
    private RegistrationService $registrationService;
    private SessionService $sessionService;
    private PlayerStateService $playerStateService;
    private VisibilityManager $visibilityManager;
    private PluginControlService $pluginControlService;
    private MigrationManager $migrationManager;
    private AuthenticationFlowManager $authenticationFlowManager;
    private TitleService $titleService;
    private LoginRateLimiter $loginRateLimiter;

    /** @var array<string, TaskHandler> */
    private array $kickTasks = [];

    /** @var array<string, string> */
    private array $deviceIds = [];

    public function __construct(
        private \Luthfi\XAuth\Main $plugin,
    ) {}

    public function boot(): void {
        $this->configData = $this->plugin->getConfig();
        $language = (string)$this->configData->get("language", "en");
        $this->languageMessages = new Config($this->plugin->getDataFolder() . "lang/" . $language . ".yml", Config::YAML);

        $this->migrationManager = new MigrationManager($this->plugin);
        $this->passwordPolicy = new PasswordPolicy($this->plugin);
        $this->formManager = new FormManager($this->plugin);
        $this->passwordHasher = new PasswordHasher($this->plugin);
        $this->visibilityManager = new VisibilityManager($this->plugin);
        $this->playerStateService = new PlayerStateService($this->plugin, $this->visibilityManager);
        $this->pluginControlService = new PluginControlService($this->plugin);
        $this->titleService = new TitleService($this->plugin);

        $this->databaseManager = new DatabaseManager($this->plugin, (array)$this->configData->get('database'));
        $this->databaseManager->connect();

        $userRepository = $this->databaseManager->getUserRepository();
        $sessionRepository = $this->databaseManager->getSessionRepository();

        $this->loginRateLimiter = new LoginRateLimiter($this->plugin, $userRepository);

        $createSession = new CreateSession($sessionRepository);
        $restoreSession = new RestoreSession($sessionRepository);
        $terminateSession = new TerminateSession($sessionRepository);
        $this->sessionService = new SessionService($this->plugin, $restoreSession, $createSession, $terminateSession);

        $registerUser = new RegisterUser($userRepository, $this->passwordHasher, $this->plugin);
        $deleteUser = new DeleteUser($userRepository, $this->passwordHasher, $this->plugin);
        $this->registrationService = new RegistrationService($this->plugin, $registerUser, $deleteUser);

        $loginUser = new LoginUser($userRepository, $this->passwordHasher, $this->loginRateLimiter);
        $logoutUser = new LogoutUser(
            $this->playerStateService,
            $this->visibilityManager,
            $this->titleService,
            $this->formManager,
            $this->plugin
        );
        $changePassword = new ChangePassword($userRepository, $this->passwordHasher, $this->plugin);
        $verifyPassword = new VerifyPassword($userRepository, $this->passwordHasher);

        $this->authenticationService = new AuthenticationService(
            $this->plugin,
            $userRepository,
            $sessionRepository,
            $this->passwordHasher,
            $this->sessionService,
            $this->playerStateService,
            $this->visibilityManager,
            $this->titleService,
            $this->formManager,
            $this->loginRateLimiter,
            $loginUser,
            $logoutUser,
            $changePassword,
            $verifyPassword
        );
    }

    public function bootFlow(): void {
        $this->authenticationFlowManager = new AuthenticationFlowManager($this->plugin);

        $this->authenticationFlowManager->registerAuthenticationStep(new \Luthfi\XAuth\Application\Auth\Pipeline\Steps\AutoLoginStep($this->plugin));
        $this->authenticationFlowManager->registerAuthenticationStep(new \Luthfi\XAuth\Application\Auth\Pipeline\Steps\XAuthLoginStep($this->plugin));
        $this->authenticationFlowManager->registerAuthenticationStep(new \Luthfi\XAuth\Application\Auth\Pipeline\Steps\XAuthRegisterStep($this->plugin));
    }

    public function getConfigData(): Config { return $this->configData; }
    public function getLanguageMessages(): Config { return $this->languageMessages; }
    public function getDatabaseManager(): DatabaseManager { return $this->databaseManager; }
    public function getUserRepository(): ?UserRepository { return $this->databaseManager?->getUserRepository(); }
    public function getSessionRepository(): ?SessionRepository { return $this->databaseManager?->getSessionRepository(); }
    public function getCustomMessages(): Config { return $this->languageMessages; }
    public function getPasswordPolicy(): PasswordPolicy { return $this->passwordPolicy; }
    public function getPasswordHasher(): PasswordHasher { return $this->passwordHasher; }
    public function getFormManager(): FormManager { return $this->formManager; }
    public function getAuthenticationService(): AuthenticationService { return $this->authenticationService; }
    public function getRegistrationService(): RegistrationService { return $this->registrationService; }
    public function getSessionService(): SessionService { return $this->sessionService; }
    public function getPlayerStateService(): PlayerStateService { return $this->playerStateService; }
    public function getVisibilityManager(): VisibilityManager { return $this->visibilityManager; }
    public function getPluginControlService(): PluginControlService { return $this->pluginControlService; }
    public function getMigrationManager(): MigrationManager { return $this->migrationManager; }
    public function getAuthenticationFlowManager(): AuthenticationFlowManager { return $this->authenticationFlowManager; }
    public function getTitleService(): TitleService { return $this->titleService; }
    public function getLoginRateLimiter(): LoginRateLimiter { return $this->loginRateLimiter; }

    public function registerAuthenticationStep(AuthenticationStep $step): void {
        $this->authenticationFlowManager->registerAuthenticationStep($step);
    }

    public function startAuthenticationStep(Player $player, ?string $startStepId = null): void {
        $this->authenticationFlowManager->startAuthenticationFlow($player, $startStepId);
    }

    public function completeAuthenticationStep(Player $player, string $completedStepId): void {
        $this->plugin->getLogger()->warning("completeAuthenticationStep is deprecated. Use AuthenticationFlowManager::completeStep or skipStep.");
        $this->authenticationFlowManager->completeStep($player, $completedStepId);
    }

    public function getPlayerAuthenticationStepStatus(Player $player, string $stepId): ?string {
        return $this->authenticationFlowManager->getPlayerAuthenticationStepStatus($player, $stepId);
    }

    /** @return array<string, AuthenticationStep> */
    public function getAuthenticationSteps(): array {
        return $this->authenticationFlowManager->getAuthenticationSteps();
    }

    public function getOrderedAuthenticationSteps(): array {
        return $this->authenticationFlowManager->getOrderedAuthenticationSteps();
    }

    public function cancelKickTask(Player $player): void {
        $name = $player->getName();
        if (isset($this->kickTasks[$name])) {
            $this->kickTasks[$name]->cancel();
            unset($this->kickTasks[$name]);
        }
    }

    public function scheduleKickTask(Player $player): void {
        $loginTimeout = (int)($this->configData->getNested("session.login-timeout") ?? 30);
        if ($loginTimeout > 0) {
            $this->kickTasks[$player->getName()] = $this->plugin->getScheduler()->scheduleDelayedTask(new KickTask($this->plugin, $player), $loginTimeout * 20);
        }
    }

    /** @return array<string, string> */
    public function &getDeviceIds(): array {
        return $this->deviceIds;
    }

    public function close(): void {
        $this->databaseManager?->close();
    }
}
