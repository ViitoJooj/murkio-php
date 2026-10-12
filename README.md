# Murkio identity for PHP

Tells who is behind each request and writes the login components into the pages you
render. PHP 8.1+ with the sodium extension (bundled with PHP). The only setting is your
publishable key.

```sh
composer require murkio/identity
MURKIO_PUBLISHABLE_KEY=pk_...    # MURKIO_API_URL is optional
```

## Plain PHP

```php
use Murkio\Murkio;

$murkio = new Murkio();

// dashboard.php — sends 401 / a redirect / the session-refresh page and stops when needed
$auth = $murkio->guard(['required' => true, 'signInUrl' => '/login.php', 'loadUser' => true]);
echo 'Hello ' . htmlspecialchars($auth->user->email);
```

```php
<!-- login.php -->
<head><?= $murkio->head(['afterLogin' => '/dashboard.php']) ?><?= $murkio->bootstrapScript() ?></head>
<body>
  <?= $murkio->canvas() ?>
  <!-- or your own layout: -->
  <?= $murkio->emailInput(['class' => 'input', 'placeholder' => 'you@example.com']) ?>
  <?= $murkio->passwordInput(['class' => 'input']) ?>
  <?= $murkio->keepLogged('Keep me signed in') ?>
  <?= $murkio->loginButton('Sign in', ['class' => 'btn']) ?>
  <?= $murkio->registerButton('Create account', ['class' => 'btn']) ?>
  <?= $murkio->errorMessage() ?>
</body>
```

## Laravel

```php
// app/Http/Middleware/MurkioAuth.php
public function handle(Request $request, Closure $next, string ...$roles)
{
    [$auth, $answer] = app(\Murkio\Murkio::class)->protect(\Murkio\Murkio::requestFromGlobals(), [
        'required' => true, 'roles' => $roles, 'signInUrl' => '/login', 'loadUser' => true,
    ]);
    if ($answer) {
        return response($answer->body, $answer->status)->withHeaders($answer->headers);
    }
    $request->attributes->set('murkio', $auth);
    return $next($request);
}
```

Register `Murkio\Murkio` as a singleton, and print the helpers in Blade with `{!! !!}`
(`{!! $murkio->canvas() !!}`): they are already escaped.

## PSR-15 (Slim, Mezzio, Laminas)

```php
$app->add(new \Murkio\Psr15Middleware($murkio, $responseFactory, ['required' => true]));
$auth = $request->getAttribute('murkio');   // ->session, ->user
```

## Cache

A PHP request starts from nothing, so what comes from the API (the application, its
signing keys, profiles) is cached between requests: APCu when it is enabled, else files
in a private directory under the system temp dir. Pass your own with
`new Murkio(null, ['cache' => $cache])` (implement `Murkio\Cache`).

## How it works

The same contract as the other server SDKs (`libs/spec/server`): `GET /v1/client` gives
the application, issuer and JWKS; access tokens are verified locally (Ed25519 with
sodium, `iss`, `aud`, `exp`); the token comes from `Authorization: Bearer` or the
`__Host-` session cookie of the browser SDK, which only counts for GET/HEAD/OPTIONS or
same-origin requests (CSRF). `loadUser` reads `POST /v1/me` (cached a minute);
`checkRevocation` asks the API whether the session was revoked (cached 30 s). A page
request with an expired cookie gets a short handshake page that refreshes it. The
backend never signs anyone in: the browser does.

## Developing

```sh
composer install
php tests/run.php
```

The tests read the token vectors every Murkio server SDK shares. That copy (`spec/`) and
the checks in `infra/pipeline/` are kept in the Murkio identity service and synced from
there, so they are not edited here.

Every pull request runs the workflows in `.github/workflows`. The same checks, locally
(the tools are the PHARs of their releases):

| Workflow | What it runs |
| --- | --- |
| Build | `composer validate --strict`, `php -l` on every file, an install without development packages that loads every class; on PHP 8.1 and 8.5 |
| Format | `php-cs-fixer fix --dry-run --diff` |
| Lint | `phpstan analyse` (level 8) |
| Tests | `php tests/run.php` on PHP 8.1 and 8.5 |
| Quality & Governance Checks | `for check in infra/pipeline/*.py; do python3 "$check"; done` |
| Security | `psalm --config=psalm.xml.dist --taint-analysis`, `composer audit`, `gitleaks git .`, `zizmor --pedantic .` |
| Dependency Review | run by GitHub on the pull request |

Security reports: see [SECURITY.md](SECURITY.md).
