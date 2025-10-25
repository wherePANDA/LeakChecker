<?php
/**
 * LeakChecker — Check if an email appears in public data breaches
 * Single-file PHP app (PHP 7.4+). Tailwind via CDN. No frameworks.
 *
 * Setup:
 * - Put your Have I Been Pwned API key in the HIBP_API_KEY env var
 *   or define it below as a constant.
 *
 * Notes:
 * - Respects HIBP v3 headers and status codes.
 * - Handles rate limiting and common error cases gracefully.
 */

// 1) Configuration -----------------------------------------------------------
$HIBP_API_KEY = getenv('HIBP_API_KEY') ?: '';      // Prefer env variable
if (!$HIBP_API_KEY) {
  // fallback (optional): define('HIBP_API_KEY', 'YOUR_API_KEY');
  // $HIBP_API_KEY = defined('HIBP_API_KEY') ? HIBP_API_KEY : '';
}

// 2) Query handling ----------------------------------------------------------
$result = null;
$error  = null;
$emailPrefill = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $email = trim($_POST['email'] ?? '');
  $emailPrefill = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');

  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $error = 'Please enter a valid email address.';
  } elseif (!$HIBP_API_KEY) {
    $error = 'Missing API key. Set HIBP_API_KEY in your environment or index.php.';
  } else {
    $endpoint = 'https://haveibeenpwned.com/api/v3/breachedaccount/' . rawurlencode($email) . '?truncateResponse=false';

    $ch = curl_init();
    curl_setopt_array($ch, [
      CURLOPT_URL            => $endpoint,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TIMEOUT        => 15,
      CURLOPT_HTTPHEADER     => [
        'hibp-api-key: ' . $HIBP_API_KEY,
        'user-agent: LeakChecker',
      ],
    ]);

    $body = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($err) {
      $error = 'Network error: ' . $err;
    } else {
      // HIBP semantics:
      // 200: breaches found (JSON array)
      // 404: not found (no breaches)
      // 400: bad request
      // 401: unauthorized (bad/missing key)
      // 403: forbidden (UA blocked, etc.)
      // 429: too many requests (rate limit)
      // 503: service unavailable
      if ($http === 200) {
        $json = json_decode($body, true);
        if (!is_array($json)) {
          $error = 'Unexpected response from API.';
        } else {
          // Normalize a few fields for display
          $result = array_map(function ($b) {
            return [
              'Name'             => $b['Name'] ?? '',
              'Title'            => $b['Title'] ?? '',
              'Domain'           => $b['Domain'] ?? '',
              'BreachDate'       => $b['BreachDate'] ?? '',
              'AddedDate'        => $b['AddedDate'] ?? '',
              'ModifiedDate'     => $b['ModifiedDate'] ?? '',
              'PwnCount'         => $b['PwnCount'] ?? 0,
              'DataClasses'      => isset($b['DataClasses']) && is_array($b['DataClasses']) ? $b['DataClasses'] : [],
              'IsVerified'       => !empty($b['IsVerified']),
              'Description'      => $b['Description'] ?? '',
              'LogoPath'         => $b['LogoPath'] ?? '',
            ];
          }, $json);
        }
      } elseif ($http === 404) {
        $result = []; // no breaches
      } elseif ($http === 400) {
        $error = 'Bad request. Check the email format.';
      } elseif ($http === 401) {
        $error = 'Unauthorized. Check your API key.';
      } elseif ($http === 403) {
        $error = 'Forbidden. Request was rejected by the API.';
      } elseif ($http === 429) {
        $error = 'Rate limit exceeded. Try again in a moment.';
      } elseif ($http === 503) {
        $error = 'Service unavailable. Try again later.';
      } else {
        $error = 'Unexpected HTTP status: ' . $http;
      }
    }
  }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>LeakChecker</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <meta name="robots" content="noindex">
</head>
<body class="min-h-screen bg-slate-950 text-slate-100">
  <main class="max-w-3xl mx-auto px-4 py-10">
    <header class="mb-8">
      <h1 class="text-3xl font-bold tracking-tight">LeakChecker</h1>
      <p class="text-slate-400 mt-2">Check whether an email address appears in known public data breaches.</p>
    </header>

    <section class="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
      <form method="POST" class="flex flex-col gap-4">
        <label class="text-sm text-slate-300" for="email">Email address</label>
        <div class="flex gap-3 flex-col sm:flex-row">
          <input
            id="email"
            name="email"
            type="email"
            required
            value="<?= $emailPrefill ?>"
            placeholder="name@example.com"
            class="w-full rounded-xl border border-slate-800 bg-slate-900 px-4 py-3 text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <button
            type="submit"
            class="shrink-0 rounded-xl bg-indigo-600 px-5 py-3 font-semibold hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            Check
          </button>
        </div>
        <p class="text-xs text-slate-500">Your email is sent only to the Have I Been Pwned API to perform the lookup. No data is stored server-side.</p>
      </form>
    </section>

    <?php if ($error): ?>
      <div class="mt-6 rounded-xl border border-red-900/40 bg-red-950/40 p-4">
        <div class="font-semibold text-red-300">Error</div>
        <div class="text-sm text-red-200 mt-1"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
      </div>
    <?php endif; ?>

    <?php if ($result !== null && !$error): ?>
      <section class="mt-6">
        <?php if (empty($result)): ?>
          <div class="rounded-xl border border-emerald-900/40 bg-emerald-950/40 p-4">
            <div class="font-semibold text-emerald-300">No breaches found</div>
            <p class="text-sm text-emerald-200 mt-1">This email does not appear in the breach database.</p>
          </div>
        <?php else: ?>
          <div class="mb-3">
            <h2 class="text-xl font-semibold">Breaches found</h2>
            <p class="text-slate-400 text-sm">Matches returned by the service for this email.</p>
          </div>

          <div class="grid gap-4">
            <?php foreach ($result as $b): ?>
              <article class="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
                <div class="flex items-start justify-between gap-3">
                  <div>
                    <h3 class="text-lg font-semibold">
                      <?= htmlspecialchars($b['Title'] ?: $b['Name'], ENT_QUOTES, 'UTF-8') ?>
                    </h3>
                    <?php if (!empty($b['Domain'])): ?>
                      <div class="text-slate-400 text-sm"><?= htmlspecialchars($b['Domain'], ENT_QUOTES, 'UTF-8') ?></div>
                    <?php endif; ?>
                  </div>
                  <?php if (!empty($b['LogoPath'])): ?>
                    <img src="<?= htmlspecialchars($b['LogoPath'], ENT_QUOTES, 'UTF-8') ?>" alt="" class="h-8 w-8 rounded-md object-cover ring-1 ring-slate-800" loading="lazy" />
                  <?php endif; ?>
                </div>

                <dl class="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
                  <div>
                    <dt class="text-slate-400">Breach date</dt>
                    <dd class="text-slate-200"><?= htmlspecialchars($b['BreachDate'], ENT_QUOTES, 'UTF-8') ?></dd>
                  </div>
                  <div>
                    <dt class="text-slate-400">Records</dt>
                    <dd class="text-slate-200"><?= number_format((int)$b['PwnCount']) ?></dd>
                  </div>
                  <div>
                    <dt class="text-slate-400">Verified</dt>
                    <dd class="text-slate-200"><?= $b['IsVerified'] ? 'Yes' : 'No' ?></dd>
                  </div>
                </dl>

                <?php if (!empty($b['DataClasses'])): ?>
                  <div class="mt-3">
                    <div class="text-slate-400 text-sm mb-1">Exposed data</div>
                    <div class="flex flex-wrap gap-2">
                      <?php foreach ($b['DataClasses'] as $dc): ?>
                        <span class="rounded-full border border-slate-800 bg-slate-900 px-2.5 py-1 text-xs text-slate-200">
                          <?= htmlspecialchars($dc, ENT_QUOTES, 'UTF-8') ?>
                        </span>
                      <?php endforeach; ?>
                    </div>
                  </div>
                <?php endif; ?>

                <?php if (!empty($b['Description'])): ?>
                  <details class="mt-3 group">
                    <summary class="cursor-pointer text-sm text-slate-300 hover:text-slate-100">Description</summary>
                    <div class="prose prose-invert max-w-none text-sm text-slate-200 mt-2">
                      <?= $b['Description'] /* API text is HTML-safe from HIBP; render as-is for formatting */ ?>
                    </div>
                  </details>
                <?php endif; ?>
              </article>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>
      </section>
    <?php endif; ?>

    <footer class="mt-10 text-center text-xs text-slate-600">
      <p>Remember to rotate passwords regularly and enable multi-factor authentication.</p>
    </footer>
  </main>
</body>
</html>