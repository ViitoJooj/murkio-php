<?php

declare(strict_types=1);

namespace Murkio;

/** An answer to send instead of running the route (401, 403, redirect or handshake). */
final class Response
{
    /** @param array<string, string> $headers */
    public function __construct(
        public readonly int $status,
        public readonly array $headers = [],
        public readonly string $body = '',
    ) {}

    /** Sends the response with PHP's own functions (plain PHP, no framework). */
    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $name => $value) {
            header($name . ': ' . $value);
        }
        echo $this->body;
    }
}
