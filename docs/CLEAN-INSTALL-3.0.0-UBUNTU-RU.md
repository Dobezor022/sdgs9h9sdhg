# FedMes 3.0.0 — clean install / upgrade на Ubuntu 24.04

FedMes 3.0 сохраняет protocol generation 4 и security epoch 1, поэтому штатное обновление с 2.0.1 выполняется с `--preserve-data`. Перед переключением systemd установщик сам собирает Rust server suite и проверяет версии бинарников.

```bash
cd deploy
export FEDMES_DOMAIN='fedmes.xuanguang.su'
sudo -E ./clean-install-3.0.0.sh --preserve-data
```

Для полностью чистой установки используется `--wipe-data`. Этот режим уничтожает локальную БД/медиа и не должен применяться при обычном обновлении.

После установки обязательны проверки:

```bash
curl -fsS https://$FEDMES_DOMAIN/health/live
curl -fsS https://$FEDMES_DOMAIN/health/ready
systemctl --no-pager --full status fedmes fedmes-updates fedmes-maintainer
```

`/health/ready` для 3.0 возвращает номер схемы, версию, build, protocol generation, security epoch и текущий event cursor. Старые API v1/v2/v3/v4 остаются доступными для совместимости с установленными 2.0.1-клиентами во время обновления.
