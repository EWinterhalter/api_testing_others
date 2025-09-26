КТ-4. Интеграционное тестирование «большого взрыва»

Запуск
```sh
go run main.go
```
Обращаться к 
```sh
localhost:8080/api/
```
### Метод
Метод интеграционного тестирования «большого взрыва» представляет собой подход, при котором все разработанные модули системы объединяются одновременно в один этап и тестируются как единое целое. 

### Тесты
POST /api/auth/register

Ожидается: 200 OK json с token, refreshToken, user (user.IsAdmin == true для первого).

POST /api/auth/register

Ожидается: 409 Conflict {"error":"Email already exists"}

POST /api/auth/login

Ожидается: 200 + tokens.

GET /api/auth/me

Ожидается: 200 + user payload.

### Выявленые проблемы
PUT /api/users/{id} не обновляет индексы (usersBy...)

DELETE /api/users/{id} не удаляет записи из индексов

Refresh token = Access token; отсутствие механизма отзывa токена

validateToken: нет проверки метода подписи и других защит

Жёстко закодированный JWT секрет

Authorization header trimming/варианты формата

Ответы: везде http.Error с JSON-строкой — шанс двойного Content-Type