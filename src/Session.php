<?php

declare(strict_types=1);

namespace Murkio;

/** A verified access token. */
final class Session
{
    /**
     * @param list<string> $roles
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public readonly string $userId,
        public readonly string $sessionId,
        public readonly string $applicationId,
        public readonly array $roles,
        public readonly array $claims,
        public readonly string $token,
    ) {
    }

    public function hasRole(string ...$roles): bool
    {
        return array_intersect($roles, $this->roles) !== [];
    }
}
