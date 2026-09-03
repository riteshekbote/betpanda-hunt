
## 2026-09-02 21:55:06 UTC


## 2026-09-02 23:53:19 UTC


## 2026-09-03 03:14:41 UTC


## 2026-09-03 08:09:50 UTC


## 2026-09-03 12:57:32 UTC


## 2026-09-03 17:05:50 UTC
https://dashboard.betpanda.io/ -> ERR <urlopen error timed out>
https://dashboard.betpanda.io/api/ -> ERR <urlopen error timed out>
https://dashboard.betpanda.io/api/v1/namespaces/kubernetes-dashboard -> ERR <urlopen error timed out>
https://affiliates.betpanda.io/ -> 200 len=?
https://affiliates.betpanda.io/api/ -> 200 len=?
https://betpanda.io/ -> 200 len=?
https://betpanda.io/api/auth/authorize?redirect_uri=https://evil.com&state=test&client_id=test -> 200 len=?
https://flags.betpanda.io` -> ERR <urlopen error [Errno -2] Name or service not know

## 2026-09-03 19:50:27 UTC
https://betpanda.io/api/auth/authorize?redirect_uri=https://attacker.com/callback&response_type=code&client_id=test&scope=openid&state=xyz -> 200 len=?
https://cable.betpanda.io/cable/user-event -> HTTP 405
https://cable.betpanda.io/cable/ -> HTTP 404
https://betpanda.io/api/auth/authorize?redirect_uri=https://httpbin.org/get&response_type=code&client_id=test&scope=openid&state=test123 -> 200 len=?
https://affiliates.betpanda.io/rest/user -> HTTP 401
https://affiliates.betpanda.io/rest/user/players -> HTTP 405
