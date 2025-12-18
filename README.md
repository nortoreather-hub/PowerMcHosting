PowerMcHosting — GPT-5 mini enablement

- **Status:** `gpt5_mini_enabled_for_all_clients` is set to `true` in `config/gpt_config.json`.

Next steps to apply change:

1. Review the config at `config/gpt_config.json`.
2. Commit the change and push to your repository.
3. Deploy via your normal deployment/CI so services pick up the new config.

Suggested commands:

```bash
git add config/gpt_config.json README.md
git commit -m "Enable GPT-5 mini for all clients"
git push
# Then trigger your CI/deploy pipeline
```

To revert, set `gpt5_mini_enabled_for_all_clients` to `false` and repeat the commit/deploy steps.
