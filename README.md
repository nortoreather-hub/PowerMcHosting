PowerMcHosting — GPT-5 mini enablement

- **Status:** `gpt5_mini_enabled_for_all_clients` is set to `true` in `config/gpt_config.json`.

Next steps to apply change:

1. Review the config at `config/gpt_config.json`.
2. Commit the change and push to your repository.
3. Deploy via your normal deployment/CI so services pick up the new config.

If you want to run the panel and proxy it to a production domain (example `powerhost.org`):

1. Add DNS A record pointing `powerhost.org` (and optionally `play.powermc.fun`) to your server public IP.
2. Use the included `docker-compose.yml` which now includes a `caddy` reverse proxy that will obtain TLS certificates automatically for `powerhost.org`.
3. Start services:

```bash
docker compose up --build -d
```

Caddy will proxy `powerhost.org` to the panel service and terminate TLS. Ensure ports 80 and 443 are reachable.


Suggested commands:

```bash
git add config/gpt_config.json README.md
git commit -m "Enable GPT-5 mini for all clients"
git push
# Then trigger your CI/deploy pipeline
```

To revert, set `gpt5_mini_enabled_for_all_clients` to `false` and repeat the commit/deploy steps.
