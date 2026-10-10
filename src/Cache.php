<?php

declare(strict_types=1);

namespace Murkio;

/**
 * Where the SDK keeps what it learns from the API between requests.
 *
 * A PHP request starts from nothing, so without a cache every page would call
 * the API for the application and its signing keys. Values are plain arrays.
 */
interface Cache
{
    /** @return array<string, mixed>|null */
    public function get(string $key): ?array;

    /** @param array<string, mixed> $value */
    public function set(string $key, array $value, int $ttl): void;
}
