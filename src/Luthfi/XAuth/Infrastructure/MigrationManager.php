<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Infrastructure;

use Luthfi\XAuth\Infrastructure\Persistence\ConnectorFactory;
use Luthfi\XAuth\Infrastructure\Persistence\SchemaManager;
use Luthfi\XAuth\Domain\User\UserRepository;
use ChernegaSergiy\Language\TranslatorInterface;
use pocketmine\plugin\PluginBase;
use pocketmine\utils\TextFormat;
use SOFe\AwaitGenerator\Await;
use Throwable;

class MigrationManager {

    private static bool $isMigrationInProgress = false;

    public function __construct(
        private PluginBase $plugin,
        private TranslatorInterface $translator,
    ) {}

    public static function isMigrationInProgress(): bool {
        return self::$isMigrationInProgress;
    }

    private static function setMigrationInProgress(bool $inProgress): void {
        self::$isMigrationInProgress = $inProgress;
    }

    public function migrate(string $sourceType, string $destinationType): void {
        if ($sourceType === $destinationType) {
            $this->plugin->getLogger()->warning("Source and destination provider types are the same ('{$sourceType}'). No migration needed.");
            return;
        }

        if (self::isMigrationInProgress()) {
            throw new \RuntimeException("A migration is already in progress.");
        }

        self::setMigrationInProgress(true);

        Await::g2c(function() use ($sourceType, $destinationType) {
            $sourceConnector = null;
            $destinationConnector = null;

            try {
                $this->plugin->getLogger()->info("Creating database connectors...");
                $sourceConnector = ConnectorFactory::create($this->plugin, $sourceType);
                $destinationConnector = ConnectorFactory::create($this->plugin, $destinationType);
                
                $sourceRepo = new UserRepository($this->plugin, $sourceConnector);
                $destinationRepo = new UserRepository($this->plugin, $destinationConnector);
                
                $sourceSchema = new SchemaManager($this->plugin, $sourceConnector);
                $destinationSchema = new SchemaManager($this->plugin, $destinationConnector);

                $sourceSchema->initialize(false);
                $destinationSchema->initialize(false);
                
                $this->plugin->getLogger()->info("Connectors created. Calculating total players from '{$sourceType}'...");
                
                $total = yield from $sourceRepo->count();
                $this->plugin->getLogger()->info($this->translator->translate($this->translator->getDefaultLocale(), "messages.xauth_migration_found_players", ['count' => (string)$total]));

                if ($total === 0) {
                    $this->plugin->getLogger()->info("Nothing to migrate.");
                } else {
                    $migratedCount = 0;
                    $skippedCount = 0;
                    $batchSize = 100;

                    for ($offset = 0; $offset < $total; $offset += $batchSize) {
                        $playerDataBatch = yield from $sourceRepo->getPaged($batchSize, $offset);

                        foreach ($playerDataBatch as $playerData) {
                            $exists = yield from $destinationRepo->exists($playerData['name']);
                            if ($exists) {
                                $skippedCount++;
                            } else {
                                yield from $destinationRepo->createRaw($playerData['name'], $playerData);
                                $migratedCount++;
                            }
                        }
                        
                        $processedCount = $offset + count($playerDataBatch);
                        $message = $this->translator->translate($this->translator->getDefaultLocale(), "messages.xauth_migration_progress", [
                            'migrated' => (string)$migratedCount,
                            'total' => (string)$total,
                            'skipped' => (string)$skippedCount
                        ]);
                        $this->plugin->getLogger()->info(TextFormat::clean($message));
                    }

                    $this->plugin->getLogger()->info($this->translator->translate($this->translator->getDefaultLocale(), "messages.xauth_migration_complete"));
                    $this->plugin->getLogger()->info($this->translator->translate($this->translator->getDefaultLocale(), "messages.xauth_migration_migrated_count", ['count' => (string)$migratedCount]));
                    $this->plugin->getLogger()->info($this->translator->translate($this->translator->getDefaultLocale(), "messages.xauth_migration_skipped_count", ['count' => (string)$skippedCount]));
                }
            } catch (Throwable $e) {
                $this->plugin->getLogger()->error("Migration failed: " . $e->getMessage());
            } finally {
                $sourceConnector?->close();
                $destinationConnector?->close();
                self::setMigrationInProgress(false);
                $this->plugin->getLogger()->info("Migration process finished and connections closed.");
            }
        });
    }
}
