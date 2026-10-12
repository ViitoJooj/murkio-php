<?php

declare(strict_types=1);

// A dependency-free test runner: `php tests/run.php`. With the dev
// dependencies installed (composer install) it also tests the PSR-15 middleware.

use Murkio\ArrayCache;
use Murkio\Cdn;
use Murkio\FileCache;
use Murkio\Murkio;
use Murkio\TokenException;

if (is_file(__DIR__ . '/../vendor/autoload.php')) {
    require __DIR__ . '/../vendor/autoload.php';
} else {
    spl_autoload_register(static function (string $class): void {
        if (str_starts_with($class, 'Murkio\\')) {
            require __DIR__ . '/../src/' . substr($class, 7) . '.php';
        }
    });
}

const KEY = 'pk_php_test';

final class FakeApi
{
    public string $secret;
    /** @var array<string, mixed> */
    public array $jwks;
    /** @var list<string> */
    public array $calls = [];
    /** @var array<string, bool> */
    public array $revoked = [];

    /** @param array<string, mixed>|null $jwks */
    public function __construct(?array $jwks = null, public string $application = 'app-1', public string $issuer = 'enterprise-auth')
    {
        $pair = sodium_crypto_sign_keypair();
        $this->secret = sodium_crypto_sign_secretkey($pair);
        $this->jwks = $jwks ?? ['keys' => [['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => 'k1', 'alg' => 'EdDSA', 'x' => b64(sodium_crypto_sign_publickey($pair))]]];
    }

    /** @return array{0: int, 1: string} */
    public function __invoke(string $method, string $url, array $headers, ?string $body): array
    {
        $path = (string) parse_url($url, PHP_URL_PATH);
        $this->calls[] = $method . ' ' . $path;
        return match ($path) {
            '/v1/client' => ($headers['Authorization'] ?? '') === 'Bearer ' . KEY
                ? [200, json_encode(['data' => ['application_id' => $this->application, 'issuer' => $this->issuer, 'jwks_url' => '/jwks.json', 'config' => [], 'canvas' => ['version' => 0, 'document' => ['note' => "</script><b>&\u{2028}"]]]])]
                : [401, json_encode(['details' => [['code' => 'bss-01']]])],
            '/jwks.json' => [200, json_encode($this->jwks)],
            '/v1/me' => [200, json_encode(['data' => ['id' => 'user-1', 'session_id' => 'session-1', 'email' => 'ana@example.com', 'email_verified' => true, 'roles' => ['user'], 'mfa_enabled' => false, 'created_at' => '2026-10-10T00:00:00Z']])],
            '/v1/sessions/verify' => [200, json_encode(['data' => ['active' => !isset($this->revoked[json_decode((string) $body, true)['access_token']])]])],
            default => [404, '{}'],
        };
    }

    /** @param array<string, mixed> $claims */
    public function token(array $claims = [], string $kid = 'k1'): string
    {
        $payload = $claims + ['iss' => $this->issuer, 'sub' => 'user-1', 'aud' => $this->application, 'aid' => $this->application, 'sid' => 'session-1', 'roles' => ['user'], 'iat' => time(), 'exp' => time() + 900, 'jti' => 'j1'];
        $signing = b64((string) json_encode(['alg' => 'EdDSA', 'kid' => $kid])) . '.' . b64((string) json_encode($payload));
        return $signing . '.' . b64(sodium_crypto_sign_detached($signing, $this->secret));
    }

    /** @param array<string, mixed> $options */
    public function client(array $options = []): Murkio
    {
        return new Murkio(KEY, $options + ['apiUrl' => 'https://api.example.com', 'transport' => $this, 'cache' => new ArrayCache()]);
    }
}

function b64(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

/** @param array<string, string> $headers @param array<string, string> $cookies @return array<string, mixed> */
function request(string $method = 'GET', array $headers = [], array $cookies = [], string $host = 'app.example.com', string $scheme = 'https', string $path = '/'): array
{
    return ['method' => $method, 'scheme' => $scheme, 'host' => $host, 'path' => $path, 'headers' => $headers, 'cookies' => $cookies];
}

$failures = 0;
$passed = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures, $passed;
    if ($ok) {
        $passed++;
        return;
    }
    $failures++;
    fwrite(STDERR, "FAIL {$name} {$detail}\n");
}

$hash = Murkio::fnv1a32(KEY);

// --- shared vectors (spec/server) --------------------------------------------
$vectors = json_decode((string) file_get_contents(__DIR__ . '/../spec/server/vectors.json'), true);
foreach ($vectors['cookie_hash'] as $value => $expected) {
    check("fnv1a32({$value})", Murkio::fnv1a32((string) $value) === $expected);
}
foreach ($vectors['cases'] as $case) {
    $client = (new FakeApi($vectors['jwks'], $vectors['application_id'], $vectors['issuer']))->client();
    $verdict = 'valid';
    $session = null;
    try {
        $session = $client->verify($case['token']);
    } catch (TokenException $error) {
        $verdict = $error->reason === 'expired' ? 'expired' : 'rejected';
    }
    check("vector: {$case['name']}", $verdict === $case['expect'], "got {$verdict}");
    if ($session !== null && isset($case['session'])) {
        check("vector session: {$case['name']}", $session->userId === $case['session']['user_id'] && $session->sessionId === $case['session']['session_id'] && $session->roles === $case['session']['roles']);
    }
}

// --- configuration and caches -------------------------------------------------
try {
    new Murkio('sk_secret');
    check('refuses secret keys', false);
} catch (InvalidArgumentException) {
    check('refuses secret keys', true);
}

$api = new FakeApi();
$client = $api->client();
$client->verify($api->token());
$client->verify($api->token());
try {
    $client->verify($api->token([], 'rotated'));
    check('unknown kid', false);
} catch (TokenException) {
    check('unknown kid', true);
}
check('bootstrap and jwks are fetched once', $api->calls === ['GET /v1/client', 'GET /jwks.json'], implode(',', $api->calls));

$directory = sys_get_temp_dir() . '/murkio-test-' . bin2hex(random_bytes(4));
$files = new FileCache($directory);
check('file cache miss', $files->get('a') === null);
$files->set('a', ['x' => 1], 60);
check('file cache hit', $files->get('a') === ['x' => 1]);
$files->set('b', ['x' => 2], -1);
check('file cache expiry', $files->get('b') === null);
check('file cache is private', (fileperms($directory) & 0777) === 0700);
array_map('unlink', glob($directory . '/*') ?: []);
rmdir($directory);

// A second "request" (a new Murkio with the same cache) calls the API for nothing.
$shared = new ArrayCache();
$api = new FakeApi();
(new Murkio(KEY, ['apiUrl' => 'https://api.example.com', 'transport' => $api, 'cache' => $shared]))->verify($api->token());
$before = count($api->calls);
(new Murkio(KEY, ['apiUrl' => 'https://api.example.com', 'transport' => $api, 'cache' => $shared]))->verify($api->token());
check('the cache carries the bootstrap and keys to the next request', count($api->calls) === $before, implode(',', $api->calls));

// --- authenticate ---------------------------------------------------------------
$api = new FakeApi();
$client = $api->client();
$token = $api->token(['roles' => ['admin']]);

$result = $client->authenticate(request('GET', ['Authorization' => 'Bearer ' . $token]));
check('bearer token', $result->session?->userId === 'user-1' && $result->session->hasRole('admin'));
check('an api key is not a session', $client->authenticate(request('GET', ['authorization' => 'Bearer ' . KEY]))->reason === 'missing');

$cookies = ["__Host-murkio_session_{$hash}" => $token, "__Host-murkio_uat_{$hash}" => '1'];
check('cookie on a navigation', $client->authenticate(request('GET', [], $cookies))->session !== null);
$blocked = $client->authenticate(request('POST', ['Sec-Fetch-Site' => 'cross-site'], $cookies));
check('cookie on a cross-site POST', $blocked->reason === 'csrf' && $blocked->signedInHint);
check('cookie on a same-origin POST', $client->authenticate(request('POST', ['Sec-Fetch-Site' => 'same-origin'], $cookies))->session !== null);
check('cookie with a matching Origin', $client->authenticate(request('POST', ['Origin' => 'https://app.example.com'], $cookies))->session !== null);
check('cookie with another Origin', $client->authenticate(request('POST', ['Origin' => 'https://evil.example'], $cookies))->reason === 'csrf');

$plain = ["murkio_session_{$hash}" => $token];
check('unprefixed cookie on a real host', $client->authenticate(request('GET', [], $plain))->reason === 'missing');
check('unprefixed cookie on localhost', $client->authenticate(request('GET', [], $plain, 'localhost:8000', 'http'))->session !== null);
$secure = ["__Secure-murkio_session_{$hash}" => $token];
check('__Secure- cookie without a cookie domain', $client->authenticate(request('GET', [], $secure))->reason === 'missing');
check('__Secure- cookie with a cookie domain', $api->client(['cookieDomain' => '.example.com'])->authenticate(request('GET', [], $secure))->session !== null);

check('expired token', $client->authenticate(request('GET', ['Authorization' => 'Bearer ' . $api->token(['exp' => 1])]))->reason === 'expired');
check('token of another application', $client->authenticate(request('GET', ['Authorization' => 'Bearer ' . $api->token(['aud' => 'app-2'])]))->reason === 'invalid');

$headers = ['Authorization' => 'Bearer ' . $token];
$client->authenticate(request('GET', $headers), ['loadUser' => true, 'checkRevocation' => true]);
$result = $client->authenticate(request('GET', $headers), ['loadUser' => true, 'checkRevocation' => true]);
check('user is loaded', $result->user?->email === 'ana@example.com');
check('user and revocation are cached', count(array_keys($api->calls, 'POST /v1/me', true)) === 1 && count(array_keys($api->calls, 'POST /v1/sessions/verify', true)) === 1);
$revoked = $api->token(['jti' => 'revoked']);
$api->revoked[$revoked] = true;
$result = $client->authenticate(request('GET', ['Authorization' => 'Bearer ' . $revoked]), ['checkRevocation' => true]);
check('revoked session', $result->session === null && $result->reason === 'revoked');

// --- protect ---------------------------------------------------------------------
$page = ['Accept' => 'text/html', 'Sec-Fetch-Mode' => 'navigate'];
[, $response] = $client->protect(request('GET', [], [], path: '/api'), ['required' => true]);
check('401 for apis', $response?->status === 401);
[, $response] = $client->protect(request('GET', $page, [], path: '/dashboard?tab=1'), ['required' => true, 'signInUrl' => '/login']);
check('redirect for pages', $response?->status === 302 && $response->headers['Location'] === '/login?redirect=%2Fdashboard%3Ftab%3D1', $response?->headers['Location'] ?? '');
[, $response] = $client->protect(request('GET', $headers), ['roles' => ['owner']]);
check('403 without the role', $response?->status === 403);
[, $response] = $client->protect(request('GET', $headers), ['roles' => ['admin']]);
check('role passes', $response === null);
[$result, $response] = $client->protect(request());
check('optional auth', $response === null && $result->session === null);

$hint = ["__Host-murkio_uat_{$hash}" => '1'];
[, $response] = $client->protect(request('GET', $page, $hint), ['required' => true]);
preg_match("{'nonce-([^']+)'}", $response->headers['Content-Security-Policy'] ?? '', $match);
check('handshake page', $response->status === 200 && str_contains($response->body, 'nonce="' . ($match[1] ?? '?') . '"') && str_contains($response->body, 'data-murkio-key="' . KEY . '"'));
check('handshake headers', str_contains($response->headers['Set-Cookie'], 'murkio_handshake=1') && str_contains($response->headers['Set-Cookie'], 'HttpOnly') && $response->headers['Cache-Control'] === 'no-store' && str_contains($response->headers['Content-Security-Policy'], 'connect-src https://api.example.com;'));
[, $response] = $client->protect(request('GET', $page, $hint + ['murkio_handshake' => '1']), ['required' => true]);
check('the guard cookie stops the loop', $response?->status === 401);
[, $response] = $client->protect(request('GET', $page, $hint), ['required' => true, 'handshake' => false]);
check('handshake can be turned off', $response?->status === 401);

// --- pages -------------------------------------------------------------------------
$head = $client->head(['afterLogin' => '/home']);
check('head pins the bundle', str_contains($head, 'integrity="' . Cdn::INTEGRITY . '"') && str_contains($head, 'crossorigin="anonymous"') && str_contains($head, 'data-murkio-after-login="/home"'), $head);
check('canvas', $client->canvas() === '<murkio-identity-canvas></murkio-identity-canvas>');
check('attributes are escaped', $client->canvas(['class' => '" onload="x', 'lightDom' => true]) === '<murkio-identity-canvas class="&quot; onload=&quot;x" light-dom></murkio-identity-canvas>', $client->canvas(['class' => '" onload="x']));
check('email input', $client->emailInput(['class' => 'input', 'placeholder' => 'you@example.com']) === '<murkio-identity-email-input class="input" placeholder="you@example.com"></murkio-identity-email-input>');
check('login button', $client->loginButton('Entrar', ['class' => 'btn']) === '<murkio-identity-login-button class="btn" label="Entrar"></murkio-identity-login-button>');
$inline = $client->bootstrapScript();
$payload = substr($inline, strpos($inline, '>') + 1, -strlen('</script>'));
check('inline bootstrap is escaped', !str_contains($inline, '</script><b>') && str_contains($inline, 'data-generated-at=') && !str_contains($payload, "\u{2028}") && json_decode($payload, true)['canvas']['document']['note'] === "</script><b>&\u{2028}");
check('self-hosted script has no pinned integrity', !str_contains($api->client(['scriptUrl' => 'https://static.example.com/murkio.js'])->head(), 'integrity'));

// --- PSR-15 (only with the dev dependencies) -----------------------------------------
if (interface_exists(\Psr\Http\Server\MiddlewareInterface::class) && class_exists(\Nyholm\Psr7\Factory\Psr17Factory::class)) {
    $factory = new \Nyholm\Psr7\Factory\Psr17Factory();
    $handler = new class ($factory) implements \Psr\Http\Server\RequestHandlerInterface {
        public function __construct(private \Nyholm\Psr7\Factory\Psr17Factory $factory) {}

        public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
        {
            $response = $this->factory->createResponse(200);
            $response->getBody()->write('hello ' . $request->getAttribute('murkio')->session->userId);
            return $response;
        }
    };
    $middleware = new \Murkio\Psr15Middleware($client, $factory, ['required' => true, 'signInUrl' => '/login']);
    $denied = $middleware->process($factory->createServerRequest('GET', 'https://app.example.com/api'), $handler);
    check('psr-15: 401', $denied->getStatusCode() === 401);
    $redirect = $middleware->process($factory->createServerRequest('GET', 'https://app.example.com/dashboard')->withHeader('Accept', 'text/html'), $handler);
    check('psr-15: redirect', $redirect->getStatusCode() === 302 && $redirect->getHeaderLine('Location') === '/login?redirect=%2Fdashboard');
    $allowed = $middleware->process($factory->createServerRequest('GET', 'https://app.example.com/api')->withHeader('Authorization', 'Bearer ' . $token), $handler);
    check('psr-15: session in the request attribute', (string) $allowed->getBody() === 'hello user-1');
} else {
    echo "(PSR-15 tests skipped: run composer install)\n";
}

echo "{$passed} passed, {$failures} failed\n";
exit($failures === 0 ? 0 : 1);
