<?php

declare(strict_types=1);

namespace Murkio;

/**
 * Murkio for a PHP backend: tells who is behind a request with only the
 * application's publishable key.
 *
 *     $murkio = new Murkio();                         // MURKIO_PUBLISHABLE_KEY
 *     $auth = $murkio->guard(['required' => true, 'signInUrl' => '/login']);
 *     echo 'Hello ' . $auth->session->userId;
 *
 * GET /v1/client gives the application, the token issuer and the JWKS, and the
 * access tokens are verified locally (Ed25519, issuer, audience, expiry). What
 * comes from the API is cached between requests (APCu, else files), so a page
 * costs no call to the API. The backend never signs anyone in: the browser SDK
 * does that, because the API rate-limits by the user's IP.
 */
final class Murkio
{
    public const DEFAULT_API_URL = 'https://api.mukio.com';

    private const BOOTSTRAP_TTL = 60;
    private const USER_TTL = 60;
    private const REVOCATION_TTL = 30;
    private const JWKS_TTL = 86400;
    private const JWKS_RETRY = 60;
    private const HANDSHAKE_GUARD = 'murkio_handshake';
    private const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

    public readonly string $publishableKey;
    public readonly string $apiUrl;
    public readonly string $keyHash;
    private ?string $cookieDomain;
    private ?string $scriptUrl;
    private ?string $integrity;
    private Cache $cache;
    /** @var callable(string, string, array<string, string>, ?string): array{0: int, 1: string} */
    private $transport;

    /**
     * @param array{apiUrl?: string, cookieDomain?: string, scriptUrl?: string, integrity?: string, timeout?: float,
     *              cache?: Cache, transport?: callable} $options
     */
    public function __construct(?string $publishableKey = null, array $options = [])
    {
        $key = $publishableKey ?? (getenv('MURKIO_PUBLISHABLE_KEY') ?: '');
        if (!str_starts_with($key, 'pk_')) {
            throw new \InvalidArgumentException("murkio: set the publishable key (or MURKIO_PUBLISHABLE_KEY) to the application's publishable key (pk_...)");
        }
        $this->publishableKey = $key;
        $this->apiUrl = rtrim($options['apiUrl'] ?? (getenv('MURKIO_API_URL') ?: self::DEFAULT_API_URL), '/');
        $this->keyHash = self::fnv1a32($key);
        $this->cookieDomain = $options['cookieDomain'] ?? null;
        $this->scriptUrl = $options['scriptUrl'] ?? (getenv('MURKIO_SCRIPT_URL') ?: null);
        $this->integrity = $options['integrity'] ?? (getenv('MURKIO_SCRIPT_INTEGRITY') ?: null);
        $this->cache = $options['cache'] ?? (ApcuCache::available() ? new ApcuCache() : new FileCache());
        $this->transport = $options['transport'] ?? self::defaultTransport((float) ($options['timeout'] ?? 10.0));
    }

    /** The hash that names the cookies of a publishable key (same as @murkio/html). */
    public static function fnv1a32(string $value): string
    {
        return hash('fnv1a32', $value);
    }

    // --- API -----------------------------------------------------------------

    private static function defaultTransport(float $timeout): callable
    {
        return static function (string $method, string $url, array $headers, ?string $body) use ($timeout): array {
            $lines = [];
            foreach ($headers as $name => $value) {
                $lines[] = $name . ': ' . $value;
            }
            if (function_exists('curl_init')) {
                $handle = curl_init($url);
                curl_setopt_array($handle, [
                    CURLOPT_CUSTOMREQUEST => $method !== '' ? $method : 'GET',
                    CURLOPT_HTTPHEADER => $lines,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT_MS => (int) ($timeout * 1000),
                    CURLOPT_FOLLOWLOCATION => false,
                ]);
                if ($body !== null) {
                    curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
                }
                $response = curl_exec($handle);
                $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
                curl_close($handle);
                return [$response === false ? 0 : $status, $response === false ? '' : (string) $response];
            }

            $context = stream_context_create(['http' => [
                'method' => $method,
                'header' => implode("\r\n", $lines),
                'content' => $body ?? '',
                'timeout' => $timeout,
                'ignore_errors' => true,
                'follow_location' => 0,
            ]]);
            $response = @file_get_contents($url, false, $context);
            $status = 0;
            if (isset($http_response_header[0]) && preg_match('{^HTTP/\S+ (\d{3})}', $http_response_header[0], $match)) {
                $status = (int) $match[1];
            }
            return [$response === false ? 0 : $status, $response === false ? '' : $response];
        };
    }

    /**
     * @param array<string, mixed>|null $body
     * @return array<string, mixed>
     */
    private function call(string $method, string $path, ?array $body = null): array
    {
        $headers = ['Authorization' => 'Bearer ' . $this->publishableKey, 'Accept' => 'application/json'];
        $payload = null;
        if ($body !== null) {
            $headers['Content-Type'] = 'application/json';
            $payload = json_encode($body, JSON_THROW_ON_ERROR);
        }
        [$status, $raw] = ($this->transport)($method, $this->apiUrl . $path, $headers, $payload);
        $decoded = json_decode($raw, true);
        if ($status < 200 || $status >= 300 || !is_array($decoded) || !isset($decoded['data']) || !is_array($decoded['data'])) {
            $code = is_array($decoded) && isset($decoded['details'][0]['code']) ? (string) $decoded['details'][0]['code'] : 'http-' . $status;
            throw new ApiException($status, $code);
        }
        return $decoded['data'];
    }

    /**
     * GET /v1/client: the application, its config and published canvas (cached a minute).
     *
     * @return array<string, mixed>
     */
    public function bootstrap(): array
    {
        $key = 'bootstrap.' . $this->keyHash;
        $cached = $this->cache->get($key);
        if ($cached !== null) {
            return $cached;
        }
        $bootstrap = $this->call('GET', '/v1/client');
        $this->cache->set($key, $bootstrap, self::BOOTSTRAP_TTL);
        return $bootstrap;
    }

    /**
     * The raw Ed25519 public key of `kid`. The JWKS is cached and fetched again
     * only for an unknown kid (a key rotation), at most once a minute.
     *
     * @param array<string, mixed> $bootstrap
     */
    private function publicKey(array $bootstrap, string $kid): string
    {
        $key = 'jwks.' . $this->keyHash;
        $cached = $this->cache->get($key) ?? ['keys' => [], 'at' => 0];
        if (isset($cached['keys'][$kid])) {
            return (string) base64_decode((string) $cached['keys'][$kid], true);
        }
        if (time() - (int) $cached['at'] < self::JWKS_RETRY) {
            throw new TokenException('unknown key');
        }

        $url = (string) ($bootstrap['jwks_url'] ?? '');
        if (!preg_match('{^https?://}', $url)) {
            $url = $this->apiUrl . '/' . ltrim($url, '/');
        }
        [$status, $raw] = ($this->transport)('GET', $url, ['Accept' => 'application/json'], null);
        $jwks = json_decode($raw, true);
        if ($status !== 200 || !is_array($jwks)) {
            throw new ApiException($status, 'http-' . $status);
        }

        $keys = [];
        foreach (($jwks['keys'] ?? []) as $jwk) {
            if (!is_array($jwk) || ($jwk['kty'] ?? '') !== 'OKP' || ($jwk['crv'] ?? '') !== 'Ed25519') {
                continue;
            }
            $material = self::base64UrlDecode((string) ($jwk['x'] ?? ''));
            if ($material !== null && strlen($material) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                $keys[(string) ($jwk['kid'] ?? '')] = base64_encode($material);
            }
        }
        $this->cache->set($key, ['keys' => $keys, 'at' => time()], self::JWKS_TTL);

        if (!isset($keys[$kid])) {
            throw new TokenException('unknown key');
        }
        return (string) base64_decode($keys[$kid], true);
    }

    private static function base64UrlDecode(string $value): ?string
    {
        if ($value === '' || preg_match('{[^A-Za-z0-9_-]}', $value)) {
            return null;
        }
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        return $decoded === false ? null : $decoded;
    }

    /** @return array<string, mixed> */
    private static function jsonSegment(string $segment): array
    {
        $decoded = self::base64UrlDecode($segment);
        $value = $decoded === null ? null : json_decode($decoded, true);
        if (!is_array($value)) {
            throw new TokenException('malformed token');
        }
        return $value;
    }

    /**
     * Verifies an access token locally: an EdDSA signature by one of the
     * application's keys, the issuer, the audience (the application) and the
     * expiry. Throws TokenException with reason `expired` or `invalid`.
     */
    public function verify(string $token): Session
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new TokenException('malformed token');
        }
        $header = self::jsonSegment($parts[0]);
        if (($header['alg'] ?? null) !== 'EdDSA') {
            throw new TokenException('unsupported algorithm');
        }

        $bootstrap = $this->bootstrap();
        $key = $this->publicKey($bootstrap, (string) ($header['kid'] ?? ''));
        $signature = self::base64UrlDecode($parts[2]);
        try {
            $valid = $signature !== null && strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES && $key !== ''
                && sodium_crypto_sign_verify_detached($signature, $parts[0] . '.' . $parts[1], $key);
        } catch (\SodiumException) {
            $valid = false;
        }
        if (!$valid) {
            throw new TokenException('invalid signature');
        }

        $claims = self::jsonSegment($parts[1]);
        $expires = $claims['exp'] ?? null;
        if (
            ($claims['iss'] ?? null) !== ($bootstrap['issuer'] ?? '')
            || ($claims['aud'] ?? null) !== ($bootstrap['application_id'] ?? '')
            || !is_string($claims['sub'] ?? null) || $claims['sub'] === ''
            || !is_string($claims['sid'] ?? null) || $claims['sid'] === ''
            || (!is_int($expires) && !is_float($expires))
        ) {
            throw new TokenException('invalid claims');
        }
        if (time() >= $expires) {
            throw new TokenException('expired token', 'expired');
        }

        $roles = is_array($claims['roles'] ?? null) ? array_values(array_map('strval', $claims['roles'])) : [];
        return new Session($claims['sub'], $claims['sid'], (string) $bootstrap['application_id'], $roles, $claims, $token);
    }

    /** The profile of the session's user (POST /v1/me), cached a minute per session. */
    public function user(Session $session): User
    {
        $key = 'user.' . $this->keyHash . '.' . $session->sessionId;
        $data = $this->cache->get($key);
        if ($data === null) {
            $data = $this->call('POST', '/v1/me', ['access_token' => $session->token]);
            $this->cache->set($key, $data, self::USER_TTL);
        }
        return new User(
            (string) ($data['id'] ?? ''),
            (string) ($data['session_id'] ?? ''),
            isset($data['email']) ? (string) $data['email'] : null,
            (bool) ($data['email_verified'] ?? false),
            array_values(array_map('strval', (array) ($data['roles'] ?? []))),
            (bool) ($data['mfa_enabled'] ?? false),
            (string) ($data['created_at'] ?? ''),
        );
    }

    /** False when the API says the session was revoked (logout, ban). Cached 30 s. */
    public function isActive(Session $session): bool
    {
        $key = 'active.' . $this->keyHash . '.' . hash('sha256', (string) ($session->claims['jti'] ?? $session->token));
        $cached = $this->cache->get($key);
        if ($cached !== null) {
            return (bool) $cached['active'];
        }
        $active = (bool) ($this->call('POST', '/v1/sessions/verify', ['access_token' => $session->token])['active'] ?? false);
        $this->cache->set($key, ['active' => $active], self::REVOCATION_TTL);
        return $active;
    }

    // --- requests ------------------------------------------------------------

    /**
     * The request fields the SDK reads, from PHP's globals.
     *
     * @return array{method: string, scheme: string, host: string, path: string, headers: array<string, string>, cookies: array<string, string>}
     */
    public static function requestFromGlobals(): array
    {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (is_string($value) && str_starts_with((string) $name, 'HTTP_')) {
                $headers[strtolower(str_replace('_', '-', substr((string) $name, 5)))] = $value;
            }
        }
        $https = ($_SERVER['HTTPS'] ?? '') !== '' && $_SERVER['HTTPS'] !== 'off';
        return [
            'method' => (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'),
            'scheme' => $https ? 'https' : 'http',
            'host' => $headers['host'] ?? (string) ($_SERVER['SERVER_NAME'] ?? 'localhost'),
            'path' => (string) ($_SERVER['REQUEST_URI'] ?? '/'),
            'headers' => $headers,
            'cookies' => array_map('strval', $_COOKIE),
        ];
    }

    /** @return list<array{0: string, 1: string}> */
    private function cookieNames(string $host): array
    {
        $names = [['__Host-murkio_session_' . $this->keyHash, '__Host-murkio_uat_' . $this->keyHash]];
        if ($this->cookieDomain !== null && $this->cookieDomain !== '') {
            $names[] = ['__Secure-murkio_session_' . $this->keyHash, '__Secure-murkio_uat_' . $this->keyHash];
        }
        $hostname = preg_match('{^\[(.+)\](:\d+)?$}', $host, $match) ? $match[1] : (string) preg_replace('{:\d+$}', '', $host);
        if (in_array($hostname, ['localhost', '127.0.0.1', '::1'], true)) {
            $names[] = ['murkio_session_' . $this->keyHash, 'murkio_uat_' . $this->keyHash];
        }
        return $names;
    }

    /**
     * Finds and verifies the session of a request.
     *
     * The token comes from `Authorization: Bearer` or from the session cookie
     * the browser SDK writes. The cookie goes with every request to the site,
     * including ones another site makes the browser send, so it only counts
     * for GET, HEAD and OPTIONS or for same-origin requests.
     *
     * @param array{method: string, scheme: string, host: string, headers: array<string, string>, cookies: array<string, string>, path?: string} $request
     * @param array{loadUser?: bool, checkRevocation?: bool} $options
     */
    public function authenticate(array $request, array $options = []): AuthResult
    {
        $headers = array_change_key_case($request['headers'], CASE_LOWER);
        $cookies = $request['cookies'];
        $names = $this->cookieNames($request['host']);

        $result = new AuthResult();
        foreach ($names as [, $uat]) {
            if (($cookies[$uat] ?? '') === '1') {
                $result->signedInHint = true;
            }
        }

        $token = '';
        $authorization = $headers['authorization'] ?? '';
        if (str_starts_with($authorization, 'Bearer ')) {
            $value = trim(substr($authorization, 7));
            if (!str_starts_with($value, 'pk_') && !str_starts_with($value, 'sk_')) {
                $token = $value;
            }
        }
        if ($token === '') {
            foreach ($names as [$name]) {
                if (($cookies[$name] ?? '') !== '') {
                    $token = $cookies[$name];
                    break;
                }
            }
            if ($token === '') {
                $result->reason = 'missing';
                return $result;
            }
            if (!in_array(strtoupper($request['method']), self::SAFE_METHODS, true) && !self::sameOrigin($headers, $request['scheme'], $request['host'])) {
                $result->reason = 'csrf';
                return $result;
            }
        }

        try {
            $session = $this->verify($token);
        } catch (TokenException $error) {
            $result->reason = $error->reason;
            return $result;
        }

        if ($options['checkRevocation'] ?? false) {
            try {
                $active = $this->isActive($session);
            } catch (ApiException) {
                $active = false;
            }
            if (!$active) {
                $result->reason = 'revoked';
                return $result;
            }
        }
        if ($options['loadUser'] ?? false) {
            try {
                $result->user = $this->user($session);
            } catch (ApiException) {
                $result->user = null;
            }
        }
        $result->session = $session;
        return $result;
    }

    /** @param array<string, string> $headers */
    private static function sameOrigin(array $headers, string $scheme, string $host): bool
    {
        if (($headers['sec-fetch-site'] ?? '') !== '') {
            return $headers['sec-fetch-site'] === 'same-origin';
        }
        return ($headers['origin'] ?? '') !== '' && $headers['origin'] === $scheme . '://' . $host;
    }

    /**
     * Authenticates a request and decides what to answer: the second item is
     * a Response to send instead of running the route (401, 403, a redirect to
     * `signInUrl` or the handshake page that refreshes an expired session
     * cookie), or null to go on.
     *
     * @param array{method: string, scheme: string, host: string, path: string, headers: array<string, string>, cookies: array<string, string>} $request
     * @param array{required?: bool, roles?: list<string>, signInUrl?: string, handshake?: bool, loadUser?: bool, checkRevocation?: bool} $options
     * @return array{0: AuthResult, 1: ?Response}
     */
    public function protect(array $request, array $options = []): array
    {
        $result = $this->authenticate($request, $options);
        $roles = $options['roles'] ?? [];
        if ($result->session !== null) {
            if ($roles !== [] && !$result->session->hasRole(...$roles)) {
                return [$result, self::json(403, 'forbidden')];
            }
            return [$result, null];
        }

        $headers = array_change_key_case($request['headers'], CASE_LOWER);
        $navigation = strtoupper($request['method']) === 'GET'
            && (($headers['sec-fetch-mode'] ?? '') === 'navigate' || str_contains($headers['accept'] ?? '', 'text/html'));
        if (
            ($options['handshake'] ?? true) && $navigation && $result->signedInHint
            && in_array($result->reason, ['missing', 'expired'], true)
            && ($request['cookies'][self::HANDSHAKE_GUARD] ?? '') === ''
        ) {
            return [$result, $this->handshake($request['scheme'])];
        }

        if (!($options['required'] ?? false) && $roles === []) {
            return [$result, null];
        }
        $signInUrl = $options['signInUrl'] ?? '';
        if ($navigation && $signInUrl !== '') {
            $location = $signInUrl . (str_contains($signInUrl, '?') ? '&' : '?') . 'redirect=' . rawurlencode($request['path']);
            return [$result, new Response(302, ['Location' => $location, 'Cache-Control' => 'no-store'])];
        }
        return [$result, self::json(401, 'unauthorized')];
    }

    /**
     * Plain PHP: authenticates the current request from the globals; when an
     * answer is due (401, 403, redirect, handshake) it sends it and stops.
     *
     * @param array{required?: bool, roles?: list<string>, signInUrl?: string, handshake?: bool, loadUser?: bool, checkRevocation?: bool} $options
     */
    public function guard(array $options = []): AuthResult
    {
        [$result, $response] = $this->protect(self::requestFromGlobals(), $options);
        if ($response !== null) {
            $response->send();
            exit;
        }
        return $result;
    }

    private static function json(int $status, string $message): Response
    {
        return new Response($status, ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store'], (string) json_encode(['error' => $message]));
    }

    private function handshake(string $scheme): Response
    {
        $nonce = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
        $script = parse_url($this->scriptUrl ?? Cdn::URL);
        $scriptOrigin = isset($script['scheme'], $script['host'])
            ? $script['scheme'] . '://' . $script['host'] . (isset($script['port']) ? ':' . $script['port'] : '')
            : 'https://cdn.jsdelivr.net';
        $api = parse_url($this->apiUrl);
        $apiOrigin = ($api['scheme'] ?? 'https') . '://' . ($api['host'] ?? '') . (isset($api['port']) ? ':' . $api['port'] : '');

        $page = '<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title></title>' . "\n"
            . $this->scriptTag(['nonce' => $nonce]) . "\n"
            . '<script nonce="' . $nonce . '">(async function(){try{var m=window.Murkio&&window.Murkio.getMurkio();'
            . 'if(m)await m.getToken();}catch(e){}location.replace(location.href);})();</script>' . "\n"
            . '</head><body></body></html>';

        return new Response(200, [
            'Content-Type' => 'text/html; charset=utf-8',
            'Cache-Control' => 'no-store',
            'Content-Security-Policy' => "default-src 'none'; script-src 'nonce-{$nonce}' {$scriptOrigin}; connect-src {$apiOrigin}; base-uri 'none'; frame-ancestors 'none'",
            'Set-Cookie' => self::HANDSHAKE_GUARD . '=1; Path=/; Max-Age=30; HttpOnly; SameSite=Lax' . ($scheme === 'https' ? '; Secure' : ''),
        ], $page);
    }

    // --- pages ---------------------------------------------------------------

    /** @param array<string, ?string> $pairs */
    private static function attributes(array $pairs): string
    {
        $output = '';
        foreach ($pairs as $name => $value) {
            if ($value !== null && $value !== '') {
                $output .= ' ' . $name . '="' . htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '"';
            }
        }
        return $output;
    }

    /** @param array{nonce?: string, afterLogin?: string, locale?: string, oauthRedirectUrl?: string} $options */
    private function scriptTag(array $options = []): string
    {
        $integrity = $this->scriptUrl !== null ? $this->integrity : Cdn::INTEGRITY;
        return '<script' . self::attributes([
            'src' => $this->scriptUrl ?? Cdn::URL,
            'integrity' => $integrity,
            'crossorigin' => $integrity !== null && $integrity !== '' ? 'anonymous' : null,
            'nonce' => $options['nonce'] ?? null,
            'data-murkio-key' => $this->publishableKey,
            'data-murkio-api' => $this->apiUrl,
            'data-murkio-locale' => $options['locale'] ?? null,
            'data-murkio-after-login' => $options['afterLogin'] ?? null,
            'data-murkio-oauth-redirect' => $options['oauthRedirectUrl'] ?? null,
        ]) . '></script>';
    }

    /**
     * The <script> that loads the browser SDK, pinned with its SRI hash. Put it in <head>.
     *
     * @param array{nonce?: string, afterLogin?: string, locale?: string, oauthRedirectUrl?: string} $options
     */
    public function head(array $options = []): string
    {
        return $this->scriptTag($options);
    }

    /**
     * Inlines GET /v1/client so the browser draws the canvas without fetching
     * it. JSON_HEX_TAG and JSON_HEX_AMP turn <, > and & into \u escapes, and
     * U+2028/U+2029 are escaped by default, so the JSON cannot end the script.
     */
    public function bootstrapScript(): string
    {
        $json = json_encode($this->bootstrap(), JSON_HEX_TAG | JSON_HEX_AMP | JSON_THROW_ON_ERROR);
        $stamp = (int) floor(microtime(true) * 1000);
        return '<script type="application/json" id="murkio-bootstrap" data-generated-at="' . $stamp . '">' . $json . '</script>';
    }

    /** @param array{screen?: string, class?: string, locale?: string, lightDom?: bool} $options */
    public function canvas(array $options = []): string
    {
        $attributes = self::attributes(['screen' => $options['screen'] ?? null, 'class' => $options['class'] ?? null, 'locale' => $options['locale'] ?? null]);
        return '<murkio-identity-canvas' . $attributes . (($options['lightDom'] ?? false) ? ' light-dom' : '') . '></murkio-identity-canvas>';
    }

    /** @param array{class?: string, form?: string, placeholder?: string, label?: string} $options */
    private static function field(string $tag, array $options): string
    {
        return '<' . $tag . self::attributes([
            'class' => $options['class'] ?? null,
            'form' => $options['form'] ?? null,
            'placeholder' => $options['placeholder'] ?? null,
            'label' => $options['label'] ?? null,
        ]) . '></' . $tag . '>';
    }

    /** @param array{class?: string, form?: string, placeholder?: string, label?: string} $options */
    public function emailInput(array $options = []): string
    {
        return self::field('murkio-identity-email-input', $options);
    }

    /** @param array{class?: string, form?: string, placeholder?: string, label?: string} $options */
    public function passwordInput(array $options = []): string
    {
        return self::field('murkio-identity-password-input', $options);
    }

    /** @param array{class?: string, form?: string} $options */
    public function keepLogged(string $label, array $options = []): string
    {
        return self::field('murkio-identity-keep-logged', $options + ['label' => $label]);
    }

    /** @param array{class?: string, form?: string} $options */
    public function loginButton(string $label, array $options = []): string
    {
        return self::field('murkio-identity-login-button', $options + ['label' => $label]);
    }

    /** @param array{class?: string, form?: string} $options */
    public function registerButton(string $label, array $options = []): string
    {
        return self::field('murkio-identity-register-button', $options + ['label' => $label]);
    }

    /** @param array{class?: string, form?: string} $options */
    public function errorMessage(array $options = []): string
    {
        return self::field('murkio-identity-error', $options);
    }
}
