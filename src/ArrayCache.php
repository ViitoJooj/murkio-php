<?php

declare(strict_types=1);

namespace Murkio;

/** A cache that lives for one process: long-running servers (Swoole, RoadRunner) and tests. */
final class ArrayCache implements Cache
{
    /** @var array<string, array{0: float, 1: array<string, mixed>}> */
    private array $entries = [];

    public function get(string $key): ?array
    {
        $entry = $this->entries[$key] ?? null;
        if ($entry === null || $entry[0] < microtime(true)) {
            return null;
        }
        return $entry[1];
    }

    public function set(string $key, array $value, int $ttl): void
    {
        $this->entries[$key] = [microtime(true) + $ttl, $value];
    }
}
