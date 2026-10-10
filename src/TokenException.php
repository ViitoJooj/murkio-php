<?php

declare(strict_types=1);

namespace Murkio;

/** The access token was refused. `reason` is `invalid` or `expired`. */
final class TokenException extends \RuntimeException
{
    public function __construct(string $message, public readonly string $reason = 'invalid')
    {
        parent::__construct($message);
    }
}
