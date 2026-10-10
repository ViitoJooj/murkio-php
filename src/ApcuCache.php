<?php

declare(strict_types=1);

namespace Murkio;

/** Shared memory between the PHP workers (the default when APCu is enabled). */
final class ApcuCache implements Cache
{
    public static function available(): bool
    {
        return function_exists('apcu_enabled') && apcu_enabled();
    }

    public function get(string $key): ?array
    {
        $value = apcu_fetch('murkio.' . $key, $found);
        return $found && is_array($value) ? $value : null;
    }

    public function set(string $key, array $value, int $ttl): void
    {
        apcu_store('murkio.' . $key, $value, $ttl);
    }
}
