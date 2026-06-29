# OWASP Top 10:2025 во Laravel — проектни датотеки

Овие датотеки го придружуваат елаборатот. Со нив можете локално да ја подигнете
ранливата апликација.

## Структура
- `docker-compose.yml` — дефиниција на контејнерите (app, web/nginx, db/mysql)
- `Dockerfile` — PHP 8.3 + екстензии + Composer
- `nginx.conf` — веб сервер конфигурација
- `app/vulnerable/` — РАНЛИВ код (намерно небезбедно)
- `app/secure/` — БЕЗБЕДЕН код со вградени Laravel заштити

## Подигнување (кратко)
1. `docker compose up -d --build`
2. `docker compose exec app bash` → `composer create-project laravel/laravel .`
3. `php artisan key:generate` → нагоди `.env` за базата → `php artisan migrate`
4. Копирај ги контролерите од `app/` во `src/app/Http/Controllers/` и регистрирај рути
5. Отвори `http://127.0.0.1:8000`

## ⚠ Безбедност
Апликацијата содржи активни ранливости. Работи само на 127.0.0.1, во изолирана
околина. Никогаш не изложувај на интернет. По завршување: `docker compose down -v`

## Скенери
```
composer require --dev larastan/larastan && ./vendor/bin/phpstan analyse app/ --level=9
composer require --dev vimeo/psalm && ./vendor/bin/psalm --taint-analysis
pip install semgrep && semgrep --config p/php --config p/security-audit app/
```
