<?php
// =============================================================
//  A04, A07, A08, A10 — ранливи и безбедни примери
// =============================================================

// -------------------------------------------------------------
// A04:2025 — Cryptographic Failures
// -------------------------------------------------------------

// РАНЛИВО: лозинка чувана со MD5 (брз, разбивлив хеш, без salt)
$user->password = md5($request->password);          // ❌
$token = base64_encode($userId);                     // ❌ кодирање, не енкрипција

// БЕЗБЕДНО: bcrypt/argon2 преку Laravel Hash facade
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Crypt;

$user->password = Hash::make($request->password);    // ✅ bcrypt со salt
if (Hash::check($request->password, $user->password)) { /* најава */ }

// За реверзибилни тајни — вистинска енкрипција (AES-256-GCM преку APP_KEY)
$encrypted = Crypt::encryptString($secret);          // ✅
$plain     = Crypt::decryptString($encrypted);


// -------------------------------------------------------------
// A07:2025 — Authentication Failures
// -------------------------------------------------------------

// РАНЛИВО: рачна најава без rate limiting, без throttle, слаби лозинки
public function login(Request $request) {
    $user = User::where('email', $request->email)->first();
    if ($user && $user->password === $request->password) {   // ❌ plain споредба
        session(['user_id' => $user->id]);
    }
}

// БЕЗБЕДНО: Laravel auth + throttling + валидација на јачина на лозинка
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\Rules\Password;

public function loginSecure(Request $request) {
    $request->validate([
        'email'    => 'required|email',
        'password' => ['required', Password::min(12)->mixedCase()->numbers()->symbols()],
    ]);

    // throttle: макс. 5 обиди во минута по IP
    $key = 'login:' . $request->ip();
    if (RateLimiter::tooManyAttempts($key, 5)) {
        abort(429, 'Премногу обиди. Обидете се повторно подоцна.');
    }

    if (! Auth::attempt($request->only('email', 'password'))) {  // ✅ hashed проверка
        RateLimiter::hit($key, 60);
        return back()->withErrors(['email' => 'Невалидни податоци за најава.']);
    }

    $request->session()->regenerate();   // ✅ спречува session fixation
}


// -------------------------------------------------------------
// A08:2025 — Software or Data Integrity Failures (несигурна десеријализација)
// -------------------------------------------------------------

// РАНЛИВО: unserialize() врз корисничко-контролиран внес -> object injection
$data = unserialize($request->input('payload'));     // ❌

// БЕЗБЕДНО: користи JSON (нема извршување на код при парсирање)
$data = json_decode($request->input('payload'), true);  // ✅
// + потпиши ги податоците ако мора да патуваат низ клиентот:
$signed = hash_hmac('sha256', $payload, config('app.key'));


// -------------------------------------------------------------
// A10:2025 — Mishandling of Exceptional Conditions
// -------------------------------------------------------------

// РАНЛИВО: APP_DEBUG=true во продукција -> целосен stack trace кон напаѓач,
// и „проголтани" исклучоци што го кријат вистинскиот проблем
try {
    $result = $service->process($input);
} catch (\Exception $e) {
    echo "Error: " . $e->getMessage();   // ❌ открива внатрешни детали
}

// БЕЗБЕДНО: APP_DEBUG=false во продукција + контролирано логирање
use Illuminate\Support\Facades\Log;

try {
    $result = $service->process($input);
} catch (\Throwable $e) {
    Log::error('Процесирањето не успеа', ['exception' => $e]);   // ✅ интерно лог
    return response()->view('errors.500', [], 500);              // ✅ генеричка порака
}
