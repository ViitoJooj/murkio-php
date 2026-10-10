<?php

declare(strict_types=1);

namespace Murkio;

/** Who is behind a request. `session` is null when nobody is signed in. */
final class AuthResult
{
    public function __construct(
        public ?Session $session = null,
        public ?User $user = null,
        /** Why there is no session: missing, invalid, expired, revoked or csrf. */
        public ?string $reason = null,
        /** The browser holds a session, even if this request's token is missing or expired. */
        public bool $signedInHint = false,
    ) {
    }
}
