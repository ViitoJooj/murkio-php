<?php

declare(strict_types=1);

namespace Murkio;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware (Slim, Mezzio, Laminas, any PSR-15 stack). The AuthResult
 * goes in the request attribute `murkio`:
 *
 *     $app->add(new Psr15Middleware($murkio, $responseFactory, ['required' => true]));
 *     $auth = $request->getAttribute('murkio');   // $auth->session, $auth->user
 *
 * Needs psr/http-server-middleware and a PSR-17 response factory.
 */
final class Psr15Middleware implements MiddlewareInterface
{
    public const ATTRIBUTE = 'murkio';

    /** @param array{required?: bool, roles?: list<string>, signInUrl?: string, handshake?: bool, loadUser?: bool, checkRevocation?: bool} $options */
    public function __construct(
        private readonly Murkio $murkio,
        private readonly ResponseFactoryInterface $responses,
        private readonly array $options = [],
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[strtolower((string) $name)] = implode(', ', $values);
        }
        $uri = $request->getUri();
        $host = $headers['host'] ?? $uri->getAuthority();

        [$result, $answer] = $this->murkio->protect([
            'method' => $request->getMethod(),
            'scheme' => $uri->getScheme() !== '' ? $uri->getScheme() : 'http',
            'host' => $host,
            'path' => $uri->getPath() . ($uri->getQuery() !== '' ? '?' . $uri->getQuery() : ''),
            'headers' => $headers,
            'cookies' => array_map('strval', $request->getCookieParams()),
        ], $this->options);

        if ($answer === null) {
            return $handler->handle($request->withAttribute(self::ATTRIBUTE, $result));
        }

        $response = $this->responses->createResponse($answer->status);
        foreach ($answer->headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        $response->getBody()->write($answer->body);
        return $response;
    }
}
