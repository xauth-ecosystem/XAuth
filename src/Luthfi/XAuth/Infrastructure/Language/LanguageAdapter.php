<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Infrastructure\Language;

use ChernegaSergiy\Language\TranslatorInterface;
use pocketmine\command\CommandSender;

/**
 * Thin adapter that exposes the legacy Config-like accessors (get/getNested/reload)
 * on top of libLanguage's PluginTranslator, so existing call sites that read
 * messages via ->get("messages.xxx") keep working while the underlying
 * translation is resolved through the virion.
 */
class LanguageAdapter {

    public function __construct(
        private TranslatorInterface $translator,
    ) {}

    public function getTranslator(): TranslatorInterface {
        return $this->translator;
    }

    /**
     * Resolves a message by key. Accepts both flat keys ("messages.login_prompt")
     * and nested access where the first segment is a section ("messages").
     */
    public function get(string $key, mixed $default = null): mixed {
        $value = $this->translator->translate($this->translator->getDefaultLocale(), $key, []);
        return $value === $key ? $default : $value;
    }

    public function getNested(string $key, mixed $default = null): mixed {
        return $this->get($key, $default);
    }

    public function reload(): void {
    }
}
