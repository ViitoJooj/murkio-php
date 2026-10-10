<?php

declare(strict_types=1);

namespace Murkio;

/** The profile of POST /v1/me. */
final class User
{
    /** @param list<string> $roles */
    public function __construct(
        public readonly string $id,
        public readonly string $sessionId,
        public readonly ?string $email,
        public readonly bool $emailVerified,
        public readonly array $roles,
        public readonly bool $mfaEnabled,
        public readonly string $createdAt,
    ) {
    }
}
