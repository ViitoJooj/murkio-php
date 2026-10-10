<?php

declare(strict_types=1);

namespace Murkio;

/** An error answer of the identity API (or the API could not be reached: status 0). */
final class ApiException extends \RuntimeException
{
    public function __construct(public readonly int $status, public readonly string $errorCode)
    {
        parent::__construct(sprintf('murkio: api answered %d (%s)', $status, $errorCode));
    }
}
