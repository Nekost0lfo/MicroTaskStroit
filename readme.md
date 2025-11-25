# Stroit Project Backend

## Кратко
Сборка включает три контейнера:
1. **API Gateway** – проксирует `v1/users` и `v1/orders`, проверяет JWT, расставляет `X-Request-ID/X-Trace-Id` и ограничивает всплески.
2. **Users Service** – регистрация, вход, профиль, админский список с пагинацией, внутренняя проверка пользователей по системному токену.
3. **Orders Service** – жизненный цикл заказов, правила доступа, публикация доменных событий, дополнительные health/state эндпоинты.

## Среды (profiles)
Каждый сервис читает `NODE_ENV` и выставляет `logLevel`/поведение в зависимости от профиля.
| Профиль | Переменные окружения | Назначение |
| --- | --- | --- |
| development | `NODE_ENV=development`, `LOG_LEVEL=debug` | Локальный запуск без мер по минимизации логов |
| test | `NODE_ENV=test`, `LOG_LEVEL=debug-verbose` | Поддерживает аналитические трассы и отдельные переменные (`JWT_SECRET`, `SERVICE_TOKEN`) |
| production | `NODE_ENV=production`, `LOG_LEVEL=info`, `RATE_LIMIT_*` | Прокси ограничивает 120 запросов/мин, трассы пинаются через `X-Trace-Id` |

Общие переменные:
- `JWT_SECRET` – общий секрет для токенов (тот же для всех сервисов).
- `SERVICE_TOKEN` и `SYSTEM_API_TOKEN` – одинаковый string для внутренних вызовов.
- `USERS_SERVICE_URL`, `ORDERS_SERVICE_URL` – базовые URL, которые проксируются шлюзом.

## Запуск
1. `docker-compose -f micro-task-template/docker-compose.yml up --build`
2. Gateway доступен на `http://localhost:8000`, пользователи и заказы на `8100`/`8200`.
3. Запросы с `Authorization: Bearer <JWT>` можно получить через `POST /v1/users/login`.

## Логи, трассировка и идентификаторы
- Используется `pino` + `pino-http`, `X-Request-ID` прокидывается цепочкой.
- `X-Trace-Id` выносится в отдельный контекст (`AsyncLocalStorage`) и попадает в каждый лог/событие.
- Rate limiting шлюза: `express-rate-limit` + `express-slow-down` (по умолчанию 120 req/min, первые 40 без задержки).

## OpenAPI и тесты
- Спецификация находится в `micro-task-template/docs/openapi.yaml`.
- В ней описаны все версии `v1`, схемы ответов, пагинация, `bearerAuth` и `/v1/health`/`/v1/status`.
- Минимальный набор тестов (Postman/Unit): регистрация, повторная регистрация с той же почтой, вход, доступ без токена, создание/получение/обновление/отмена заказа, защита ролей.

## Доменные события
- При создании заказа и смене статуса вызывается `events.publish`, который логирует `traceId` и служит заглушкой под брокер сообщений (будет расширено в следующих итерациях).

## Проверка состояния
- Gateway: `GET /v1/health`, `GET /v1/status`.
- Users: `GET /v1/health`, `GET /v1/status`.
- Orders: `GET /v1/orders/health`, `GET /v1/orders/status`.

Подробнее см. OpenAPI и `docs` директорию.
