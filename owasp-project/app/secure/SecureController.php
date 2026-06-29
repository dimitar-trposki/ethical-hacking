<?php
// =============================================================
//  БЕЗБЕДЕН КОД — користи вградени Laravel заштити
//  app/Http/Controllers/Secure/SecureController.php
// =============================================================

namespace App\Http\Controllers\Secure;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Auth;
use App\Models\Product;
use App\Models\Document;

class SecureController extends Controller
{
    // -------------------------------------------------------------
    // A05 — Заштита од SQL Injection
    // Eloquent / Query Builder користат PDO prepared statements;
    // вредностите се bind-уваат, никогаш не се конкатенираат.
    // -------------------------------------------------------------
    public function search(Request $request)
    {
        $validated = $request->validate([
            'q' => 'nullable|string|max:100',
        ]);

        $q = $validated['q'] ?? '';

        // БЕЗБЕДНО: Query Builder со параметризирано барање (bound parameter)
        $results = Product::where('name', 'LIKE', '%' . $q . '%')->get();

        // Алтернатива со raw, но сепак параметризирано:
        // $results = DB::select('SELECT * FROM products WHERE name LIKE ?', ['%'.$q.'%']);

        return view('secure.search', ['results' => $results]);
    }

    // -------------------------------------------------------------
    // A05 — Заштита од XSS
    // Blade автоматски escape-ира преку {{ $name }} (htmlspecialchars).
    // Доволно е да НЕ го користиме небезбедниот {!! !!} оператор.
    // -------------------------------------------------------------
    public function greet(Request $request)
    {
        $validated = $request->validate([
            'name' => 'nullable|string|max:50',
        ]);

        // БЕЗБЕДНО: внесот ќе се прикаже со {{ $name }} во Blade -> auto-escaped
        return view('secure.greet', ['name' => $validated['name'] ?? 'Гостин']);
    }

    // -------------------------------------------------------------
    // A01 — Заштита од Broken Access Control (IDOR)
    // Авторизација преку Policy / проверка на сопственост.
    // -------------------------------------------------------------
    public function showDocument($id)
    {
        $document = Document::findOrFail($id);

        // БЕЗБЕДНО: експлицитна проверка на сопственост
        // (или: $this->authorize('view', $document); со Policy)
        if ($document->user_id !== Auth::id()) {
            abort(403, 'Немате пристап до овој ресурс.');
        }

        return view('secure.document', ['document' => $document]);
    }

    // -------------------------------------------------------------
    // A01 — Заштита од SSRF
    // Дозволи само whitelist на домени; блокирај внатрешни адреси.
    // -------------------------------------------------------------
    public function fetchUrl(Request $request)
    {
        $validated = $request->validate([
            'url' => 'required|url',
        ]);

        $host = parse_url($validated['url'], PHP_URL_HOST);

        // БЕЗБЕДНО: дозволи само експлицитно одобрени домени
        $allowedHosts = ['api.partner-example.com', 'cdn.example.com'];

        if (! in_array($host, $allowedHosts, true)) {
            abort(403, 'Овој домен не е дозволен.');
        }

        // Дополнително: резолвирај IP и одбиј приватни опсези (127.0.0.0/8, 10/8, 169.254/16 ...)
        $ip = gethostbyname($host);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            abort(403, 'Пристапот до внатрешни адреси е забранет.');
        }

        $response = Http::timeout(5)->get($validated['url']);

        return response($response->body());
    }
}
