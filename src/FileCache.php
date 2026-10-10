<?php

declare(strict_types=1);

namespace Murkio;

/**
 * Files in a private directory (the default without APCu). Each value is
 * written to a temporary file and renamed, so a reader never sees half a file.
 */
final class FileCache implements Cache
{
    private string $directory;

    public function __construct(?string $directory = null)
    {
        $this->directory = $directory ?? sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'murkio-' . substr(hash('sha256', __DIR__), 0, 12);
    }

    private function path(string $key): string
    {
        return $this->directory . DIRECTORY_SEPARATOR . hash('sha256', $key) . '.json';
    }

    public function get(string $key): ?array
    {
        $raw = @file_get_contents($this->path($key));
        if ($raw === false) {
            return null;
        }
        $entry = json_decode($raw, true);
        if (!is_array($entry) || !isset($entry['expires'], $entry['value']) || $entry['expires'] < time() || !is_array($entry['value'])) {
            return null;
        }
        return $entry['value'];
    }

    public function set(string $key, array $value, int $ttl): void
    {
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0700, true) && !is_dir($this->directory)) {
            return;
        }
        $temporary = $this->path($key) . '.' . bin2hex(random_bytes(6)) . '.tmp';
        if (@file_put_contents($temporary, json_encode(['expires' => time() + $ttl, 'value' => $value]), LOCK_EX) === false) {
            return;
        }
        @chmod($temporary, 0600);
        @rename($temporary, $this->path($key));
    }
}
