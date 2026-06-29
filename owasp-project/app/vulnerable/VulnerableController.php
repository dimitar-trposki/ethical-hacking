<?php
// =============================================================
//  РАНЛИВ КОД — НАМЕРНО НЕБЕЗБЕДНО. НЕ КОРИСТЕТЕ ВО ПРОДУКЦИЈА!
//  app/Http/Controllers/Vulnerable/VulnerableController.php
// =============================================================

namespace App\Http\Controllers\Vulnerable;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use App\Models\User;
use App\Models\Document;

class VulnerableController extends Controller
{
    // -------------------------------------------------------------
    // A05:2025 — Injection (SQL Injection)
    // Корисничкиот внес се вградува директно во SQL стрингот.
    // Напад:  /search?q=' OR '1'='1
    //         /search?q='; DROP TABLE users;--
    // -------------------------------------------------------------
    public function search(Request $request)
    {
        $q = $request->query('q');

        // РАНЛИВО: директна конкатенација на корисничкиот внес во SQL
        $results = DB::select("SELECT * FROM products WHERE name LIKE '%$q%'");

        return view('vulnerable.search', ['results' => $results]);
    }

    // -------------------------------------------------------------
    // A05:2025 — Injection (Reflected XSS)
    // Корисничкиот внес се прикажува без escaping преку {!! !!}
    // Напад:  /greet?name=<script>alert(document.cookie)</script>
    // -------------------------------------------------------------
    public function greet(Request $request)
    {
        $name = $request->query('name');

        // РАНЛИВО: внесот се предава како „raw" и Blade го прикажува со {!! $name !!}
        return view('vulnerable.greet', ['name' => $name]);
    }

    // -------------------------------------------------------------
    // A01:2025 — Broken Access Control (IDOR)
    // Нема проверка дали документот ѝ припаѓа на најавената сметка.
    // Напад:  /document/1, /document/2, /document/3 ... (енумерација)
    // -------------------------------------------------------------
    public function showDocument($id)
    {
        // РАНЛИВО: го враќаме документот само врз основа на ID, без авторизација
        $document = Document::find($id);

        return view('vulnerable.document', ['document' => $document]);
    }

    // -------------------------------------------------------------
    // A01:2025 — Broken Access Control (SSRF, сега дел од A01)
    // Серверот презема произволен URL даден од корисникот.
    // Напад:  /fetch?url=http://169.254.169.254/latest/meta-data/
    //         /fetch?url=http://localhost:3306
    // -------------------------------------------------------------
    public function fetchUrl(Request $request)
    {
        $url = $request->query('url');

        // РАНЛИВО: серверот слепо презема каков било внатрешен/надворешен ресурс
        $content = file_get_contents($url);

        return response($content);
    }
}
