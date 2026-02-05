<?php

declare(strict_types=1);

namespace Luthfi\XAuth\utils;

use Luthfi\XAuth\database\ConnectorFactory;
use Luthfi\XAuth\database\SchemaManager;
use Luthfi\XAuth\repository\UserRepository;
use Luthfi\XAuth\Main;
use pocketmine\utils\TextFormat;
use SOFe\AwaitGenerator\Await;
use Throwable;

class MigrationManager {

    private Main $plugin;

    private static bool $isMigrationInProgress = false;

    public function __construct(Main $plugin) {
        $this->plugin = $plugin;
    }

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
            $messages = (array)$this->plugin->getCustomMessages()->get("messages");

            try {
                $this->plugin->getLogger()->info("Creating database connectors...");
                $sourceConnector = ConnectorFactory::create($this->plugin, $sourceType);
                $destinationConnector = ConnectorFactory::create($this->plugin, $destinationType);
                
                $sourceRepo = new UserRepository($this->plugin, $sourceConnector);
                $destinationRepo = new UserRepository($this->plugin, $destinationConnector);
                
                $sourceSchema = new SchemaManager($this->plugin, $sourceConnector);
                $destinationSchema = new SchemaManager($this->plugin, $destinationConnector);

                // Initialize tables asynchronously
                $sourceSchema->initialize(false);
                $destinationSchema->initialize(false);
                
                // We can wait a bit or assumes inserts will queue up. 
                // Ideally we should yield a simple query to ensure connection is ready, but init calls are fine.
                
                $this->plugin->getLogger()->info("Connectors created. Calculating total players from '{$sourceType}'...");
                
                $total = yield from $sourceRepo->count();
                $this->plugin->getLogger()->info(str_replace('{count}', (string)$total, (string)($messages["xauth_migration_found_players"] ?? "Found {count} players to migrate.")));

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
                        $message = (string)($messages["xauth_migration_progress"] ?? "§aMigrated: {processed}/{total} (Skipped: {skipped})");
                        $message = str_replace(['{processed}', '{total}', '{skipped}'], [(string)$processedCount, (string)$total, (string)$skippedCount], $message);
                        $this->plugin->getLogger()->info(TextFormat::clean($message));
                    }

                    $this->plugin->getLogger()->info((string)($messages["xauth_migration_complete"] ?? "Migration complete!"));
                    $this->plugin->getLogger()->info(str_replace('{count}', (string)$migratedCount, (string)($messages["xauth_migration_migrated_count"] ?? "- Migrated: {count} players")));
                    $this->plugin->getLogger()->info(str_replace('{count}', (string)$skippedCount, (string)($messages["xauth_migration_skipped_count"] ?? "- Skipped (already exist): {count} players")));
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
