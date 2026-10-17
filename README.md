# singbox-to-links

Universal converter: **sing-box JSON config → share links** (`vless://`, `trojan://`, `vmess://`, `ss://`).

Supports single JSON files/URLs and text files with lists of URLs. Multi-user configs, WS/gRPC/HTTP transports, TLS/SNI, multiplex detection (noted in output).

## Usage

```bash
pip install requests
python3 singbox_to_links.py all_configs.txt -o links.md --by-users
```

## Options

- `input` — `.txt` with `.json` URLs, or a single `.json` file/URL
- `-o, --output` — output file (default stdout)
- `--by-users` — group links by user/remark
- `--timeout` — HTTP timeout seconds
- `--workers` — parallel downloads

## Example output

```
vless://uuid@host:443?encryption=none&security=tls&sni=host&type=ws&path=%2Fpath#remark
trojan://password@host:443?security=tls&sni=host&type=ws&path=%2Fpath#remark
```

## License

MIT
