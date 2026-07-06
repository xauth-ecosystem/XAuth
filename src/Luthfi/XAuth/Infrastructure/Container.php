<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Infrastructure;

use Ifera\ScoreHud\ScoreHud;
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
use Luthfi\XAuth\Infrastructure\Scheduler\CleanupSessionsTask;
use Luthfi\XAuth\Presentation\Command\LoginCommand;
use Luthfi\XAuth\Presentation\Command\LogoutCommand;
use Luthfi\XAuth\Presentation\Command\RegisterCommand;
use Luthfi\XAuth\Presentation\Command\ResetPasswordCommand;
use Luthfi\XAuth\Presentation\Command\UnregisterCommand;
use Luthfi\XAuth\Presentation\Command\XAuthCommand;
use Luthfi\XAuth\Presentation\Expansion\XAuthExpansion;
use Luthfi\XAuth\Presentation\Form\FormManager;
use Luthfi\XAuth\Presentation\Listener\GeoIPListener;
use Luthfi\XAuth\Presentation\Listener\PlayerActionListener;
use Luthfi\XAuth\Presentation\Listener\PlayerSessionListener;
use Luthfi\XAuth\Presentation\Listener\ScoreHudListener;
use Luthfi\XAuth\Presentation\Listener\WaterdogFixListener;
use Luthfi\XAuth\Presentation\Title\TitleService;
use Luthfi\XAuth\Domain\Session\SessionRepository;
use Luthfi\XAuth\Domain\User\UserRepository;
use Luthfi\XAuth\Application\Auth\AuthenticationService;
use Luthfi\XAuth\Application\Player\PlayerStateService;
use Luthfi\XAuth\Application\User\RegistrationService;
use Luthfi\XAuth\Application\Session\SessionService;
use Luthfi\XAuth\Application\Auth\Pipeline\AuthenticationFlowManager;
use Luthfi\XAuth\Application\Auth\Pipeline\Steps\AutoLoginStep;
use Luthfi\XAuth\Application\Auth\Pipeline\Steps\XAuthLoginStep;
use Luthfi\XAuth\Application\Auth\Pipeline\Steps\XAuthRegisterStep;
use pocketmine\plugin\PluginBase;
use pocketmine\utils\Config;

class Container {

    private DatabaseManager $databaseManager;
    private Config $configData;
    private Config $languageMessages;
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
    private FormManager $formManager;
    private KickTaskManager $kickTaskManager;
    private DeviceIdStore $deviceIdStore;

    public function __construct(
        private PluginBase $plugin,
    ) {}

    public function boot(): void {
        // ─── Resources ───────────────────────────────────────────────

        $this->plugin->saveDefaultConfig();
        $this->plugin->saveResource("lang/en.yml");
        $this->plugin->saveResource("lang/id.yml");
        $this->plugin->saveResource("lang/ru.yml");
        $this->plugin->saveResource("lang/uk.yml");

        $this->configData = $this->plugin->getConfig();
        $language = (string)$this->configData->get("language", "en");
        $this->languageMessages = new Config($this->plugin->getDataFolder() . "lang/" . $language . ".yml", Config::YAML);

        // ─── Simple services (no dependencies) ───────────────────────

        $this->deviceIdStore = new DeviceIdStore();
        $this->passwordHasher = new PasswordHasher($this->plugin);
        $this->passwordPolicy = new PasswordPolicy($this->plugin, $this->languageMessages);
        $this->loginRateLimiter = new LoginRateLimiter($this->plugin);
        $this->playerStateService = new PlayerStateService($this->plugin);
        $this->migrationManager = new MigrationManager($this->plugin, $this->languageMessages);

        // ─── Kick task manager (auth service set later) ──────────────

        $this->kickTaskManager = new KickTaskManager($this->plugin, $this->configData, $this->languageMessages);

        // ─── Database ────────────────────────────────────────────────

        $this->databaseManager = new DatabaseManager($this->plugin, (array)$this->configData->get('database'));
        $this->databaseManager->connect();

        $userRepository = $this->databaseManager->getUserRepository();
        $sessionRepository = $this->databaseManager->getSessionRepository();

        // ─── Circular-aware services (auth wire later) ───────────────

        $this->visibilityManager = new VisibilityManager($this->plugin, $this->configData, $this->languageMessages);

        $createSession = new CreateSession($sessionRepository);
        $restoreSession = new RestoreSession($sessionRepository);
        $terminateSession = new TerminateSession($sessionRepository);
        $this->sessionService = new SessionService($this->plugin, $restoreSession, $createSession, $terminateSession, $this->deviceIdStore);

        $this->titleService = new TitleService($this->plugin, $this->configData, $this->languageMessages);

        // ─── Use cases without auth dependency ───────────────────────

        $registerUser = new RegisterUser($userRepository, $this->passwordHasher, $this->plugin, $this->passwordPolicy, $this->kickTaskManager);
        $loginUser = new LoginUser($userRepository, $this->passwordHasher, $this->loginRateLimiter);
        $changePassword = new ChangePassword($userRepository, $this->passwordHasher, $this->plugin, $this->passwordPolicy);
        $verifyPassword = new VerifyPassword($userRepository, $this->passwordHasher);

        // ─── LogoutUser (no longer needs FormManager) ────────────────

        $logoutUser = new LogoutUser(
            $this->playerStateService,
            $this->visibilityManager,
            $this->titleService,
            $this->plugin,
            $this->kickTaskManager,
            $userRepository,
            $this->languageMessages,
        );

        // ─── Authentication service ──────────────────────────────────

        $this->authenticationService = new AuthenticationService(
            $this->plugin,
            $userRepository,
            $sessionRepository,
            $this->passwordHasher,
            $this->sessionService,
            $this->playerStateService,
            $this->visibilityManager,
            $this->titleService,
            $this->loginRateLimiter,
            $loginUser,
            $logoutUser,
            $changePassword,
            $verifyPassword,
            $this->kickTaskManager,
            $this->passwordPolicy,
        );

        // ─── Resolve circular deps ───────────────────────────────────

        $this->visibilityManager->setAuthenticationService($this->authenticationService);
        $this->sessionService->setAuthenticationService($this->authenticationService);
        $this->kickTaskManager->setAuthenticationService($this->authenticationService);

        // ─── Use cases with auth dependency ──────────────────────────

        $deleteUser = new DeleteUser($userRepository, $this->passwordHasher, $this->plugin, $this->languageMessages, $this->authenticationService);
        $this->registrationService = new RegistrationService($this->plugin, $registerUser, $deleteUser, $this->authenticationService);

        // ─── Services with auth dependency ───────────────────────────

        $this->pluginControlService = new PluginControlService($this->plugin, $this->languageMessages, $this->visibilityManager);

        // ─── Form manager (auth & auth-flow set via setters) ─────────

        $this->formManager = new FormManager(
            $this->plugin,
            $this->languageMessages,
            $this->configData,
            $this->registrationService,
        );

        // ─── Wire remaining circular deps ────────────────────────────

        $this->authenticationService->setFormManager($this->formManager);
        $logoutUser->setFormManager($this->formManager);
        $this->formManager->setAuthenticationService($this->authenticationService);

        // ─── Config version check ────────────────────────────────────

        $this->checkConfigVersion();
    }

    public function registerFramework(): void {
        $this->bootFlow();

        // ─── Auto-login cleanup ─────────────────────────────────────────

        if ((bool)($this->configData->getNested("auto-login.enabled") ?? false)) {
            $cleanupInterval = (int)($this->configData->getNested("auto-login.cleanup_interval_minutes") ?? 60);
            $this->plugin->getScheduler()->scheduleRepeatingTask(
                new CleanupSessionsTask($this->plugin, $this->databaseManager?->getSessionRepository()),
                $cleanupInterval * 20 * 60
            );
            $this->plugin->getLogger()->debug("Expired session cleanup task scheduled.");
        }

        // ─── Listeners ──────────────────────────────────────────────────

        $this->plugin->getServer()->getPluginManager()->registerEvents(
            new PlayerActionListener($this->plugin, $this->authenticationService, $this->languageMessages),
            $this->plugin
        );
        $this->plugin->getServer()->getPluginManager()->registerEvents(
            new PlayerSessionListener($this->plugin, $this->authenticationService, $this->languageMessages, $this->deviceIdStore, $this->databaseManager?->getUserRepository(), $this->authenticationFlowManager),
            $this->plugin
        );

        if ((bool)($this->configData->getNested("waterdog-fix.enabled") ?? false)) {
            if ($this->plugin->getServer()->getConfigGroup()->getPropertyBool("player.verify-xuid", true)) {
                $this->plugin->getLogger()->warning("XAuth's WaterdogPE fix may not work correctly. To prevent issues, set 'player.verify-xuid' in pocketmine.yml to 'false'");
            }
            if ($this->plugin->getServer()->getOnlineMode()) {
                $this->plugin->getLogger()->alert("XAuth's WaterdogPE fix is not compatible with online mode. Please set 'xbox-auth' in server.properties to 'off'");
            }
            $this->plugin->getServer()->getPluginManager()->registerEvents(
                new WaterdogFixListener($this->plugin, $this->languageMessages),
                $this->plugin
            );
            $this->plugin->getLogger()->info("WaterdogPE fix enabled!");
        }

        if ((bool)(($this->configData->getNested("geoip.enabled") ?? false))) {
            $this->plugin->getServer()->getPluginManager()->registerEvents(
                new GeoIPListener($this->plugin, $this->languageMessages),
                $this->plugin
            );
        }

        $scoreHudPlugin = $this->plugin->getServer()->getPluginManager()->getPlugin("ScoreHud");
        if ($scoreHudPlugin instanceof ScoreHud) {
            $this->plugin->getServer()->getPluginManager()->registerEvents(
                new ScoreHudListener($this->authenticationService, $this->databaseManager?->getUserRepository(), $this->languageMessages, $this->plugin),
                $this->plugin
            );
        }

        $placeholderAPI = $this->plugin->getServer()->getPluginManager()->getPlugin("PlaceholderAPI");
        if ($placeholderAPI instanceof \MohamadRZ4\Placeholder\PlaceholderAPI) {
            $placeholderAPI->registerExpansion(
                new XAuthExpansion($this->authenticationService, $this->languageMessages, $this->plugin)
            );
        }

        // ─── Commands ───────────────────────────────────────────────────

        $this->plugin->getServer()->getCommandMap()->register("register", new RegisterCommand($this->registrationService, $this->authenticationFlowManager, $this->languageMessages, $this->plugin));
        $this->plugin->getServer()->getCommandMap()->register("login", new LoginCommand($this->authenticationService, $this->authenticationFlowManager, $this->languageMessages, $this->plugin));
        $this->plugin->getServer()->getCommandMap()->register("resetpassword", new ResetPasswordCommand($this->authenticationService, $this->formManager, $this->languageMessages, $this->plugin));
        $this->plugin->getServer()->getCommandMap()->register("logout", new LogoutCommand($this->authenticationService, $this->languageMessages, $this->plugin));
        $this->plugin->getServer()->getCommandMap()->register("unregister", new UnregisterCommand($this->authenticationService, $this->registrationService, $this->languageMessages, $this->plugin));
        $this->plugin->getServer()->getCommandMap()->register("xauth", new XAuthCommand($this->authenticationService, $this->registrationService, $this->sessionService, $this->pluginControlService, $this->migrationManager, $this->languageMessages, $this->plugin));
    }

    private function checkConfigVersion(): void {
        $currentVersion = (float)$this->configData->get("config-version", 1.0);
        if ($currentVersion < 1.0) {
            $message = (string)(((array)$this->languageMessages->get("messages"))["config_outdated_warning"] ?? "Your config.yml is outdated! Please update it to the latest version.");
            $this->plugin->getLogger()->warning($message);
        }
    }

    private function bootFlow(): void {
        $this->authenticationFlowManager = new AuthenticationFlowManager(
            $this->plugin,
            $this->configData,
            $this->languageMessages,
            $this->formManager,
            $this->titleService,
            $this->playerStateService,
            $this->authenticationService,
            $this->kickTaskManager,
            $this->databaseManager?->getUserRepository(),
        );

        $this->formManager->setAuthenticationFlowManager($this->authenticationFlowManager);

        $this->authenticationFlowManager->registerAuthenticationStep(new AutoLoginStep(
            $this->plugin,
            $this->configData,
            $this->languageMessages,
            $this->titleService,
            $this->authenticationFlowManager,
            $this->databaseManager?->getSessionRepository(),
            $this->deviceIdStore,
        ));
        $this->authenticationFlowManager->registerAuthenticationStep(new XAuthLoginStep(
            $this->plugin,
            $this->configData,
            $this->languageMessages,
            $this->formManager,
            $this->titleService,
            $this->authenticationService,
            $this->playerStateService,
            $this->authenticationFlowManager,
            $this->databaseManager?->getUserRepository(),
            $this->kickTaskManager,
        ));
        $this->authenticationFlowManager->registerAuthenticationStep(new XAuthRegisterStep(
            $this->plugin,
            $this->configData,
            $this->languageMessages,
            $this->formManager,
            $this->titleService,
            $this->authenticationService,
            $this->playerStateService,
            $this->authenticationFlowManager,
            $this->databaseManager?->getUserRepository(),
            $this->kickTaskManager,
        ));
    }

    public function close(): void {
        $this->databaseManager?->close();
    }
}
