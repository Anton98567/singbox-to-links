#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("Требуется библиотека requests. Установи: pip install requests", file=sys.stderr)
    sys.exit(1)

JSON_URL_RE = re.compile(r'(https?://[^\s\'"<>()\[\]{}]+?\.json(?:[^\s\'"<>()\[\]{}]*)?)', re.IGNORECASE)
TRAILING_PUNCT = re.compile(r'[\)\]\},;\'"]+$')


def clean_url(u: str) -> str:
    u = TRAILING_PUNCT.sub('', u)
    return u.strip()


def extract_json_urls(text: str) -> List[str]:
    urls = []
    for m in JSON_URL_RE.finditer(text):
        urls.append(clean_url(m.group(1)))
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def load_local_or_remote(url_or_path: str, timeout: int = 20) -> Tuple[Optional[Dict[str, Any]], Optional[str], str]:
    p = urlparse(url_or_path)
    if p.scheme in ('http', 'https'):
        try:
            r = requests.get(url_or_path, timeout=timeout, headers={'User-Agent': 'singbox-to-links/1.0'})
            r.raise_for_status()
            try:
                data = r.json()
            except Exception:
                try:
                    data = json.loads(r.text)
                except Exception as e:
                    return None, f"JSON parse error: {e}", url_or_path
            fname = os.path.basename(p.path) or p.netloc
            return data, None, fname
        except requests.RequestException as e:
            return None, f"HTTP error: {e}", url_or_path
    else:
        path = url_or_path
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                text = f.read()
            data = json.loads(text)
            return data, None, os.path.basename(path)
        except Exception as e:
            return None, f"File error: {e}", path
def build_vless_link(out: Dict[str, Any], remark_base: str) -> Optional[str]:
    try:
        server = out.get('server')
        sport = out.get('server_port') or out.get('port')
        uuid = out.get('uuid')
        if not (server and sport and uuid):
            return None
        tls = out.get('tls') or {}
        security = 'tls' if tls.get('enabled') is True else 'none'
        sni = tls.get('server_name') or tls.get('sni') or server
        alpn = tls.get('alpn')
        fp = tls.get('utls') and tls.get('utls', {}).get('fingerprint')
        allow_insecure = tls.get('insecure') or tls.get('allow_insecure')
        transport = out.get('transport') or {}
        ttype = (transport.get('type') or '').lower()
        params = []
        params.append("encryption=none")
        params.append(f"security={security}")
        if sni:
            params.append(f"sni={quote(sni, safe='')}")
        if allow_insecure is True:
            params.append("allowInsecure=1")
        if alpn:
            if isinstance(alpn, list):
                params.append(f"alpn={quote(','.join(alpn), safe='')}")
            else:
                params.append(f"alpn={quote(str(alpn), safe='')}")
        if fp:
            params.append(f"fp={quote(fp, safe='')}")
        if ttype == 'ws':
            params.append("type=ws")
            ws_path = transport.get('path') or ''
            if ws_path:
                params.append(f"path={quote(ws_path, safe='')}")
            ws_headers = transport.get('headers') or {}
            ws_host = ws_headers.get('Host') or ws_headers.get('host')
            if ws_host:
                params.append(f"host={quote(ws_host, safe='')}")
        elif ttype == 'grpc':
            params.append("type=grpc")
            grpc_sn = transport.get('service_name') or transport.get('serviceName')
            if grpc_sn:
                params.append(f"serviceName={quote(grpc_sn, safe='')}")
        elif ttype == 'http' or ttype == 'h2':
            params.append("type=http")
            h_path = transport.get('path') or '/'
            if h_path:
                params.append(f"path={quote(h_path, safe='')}")
            h_host = (transport.get('headers') or {}).get('Host') or (transport.get('headers') or {}).get('host')
            if h_host:
                params.append(f"host={quote(h_host, safe='')}")
        flow = out.get('flow')
        if flow:
            params.append(f"flow={quote(flow, safe='')}")
        tag = out.get('tag') or ''
        remark = remark_base
        if tag:
            remark = f"{remark_base} | {tag}"
        remark_clean = remark.replace('#', ' ').strip()
        qs = '&'.join(params)
        link = f"vless://{uuid}@{server}:{sport}?{qs}#{quote(remark_clean, safe='')}"
        return link
    except Exception:
        return None


def build_trojan_link(out: Dict[str, Any], remark_base: str) -> Optional[str]:
    try:
        server = out.get('server')
        sport = out.get('server_port') or out.get('port')
        pwd = out.get('password') or out.get('passwd')
        if not (server and sport and pwd):
            return None
        tls = out.get('tls') or {}
        security = 'tls' if tls.get('enabled') is True else 'none'
        sni = tls.get('server_name') or tls.get('sni') or server
        alpn = tls.get('alpn')
        fp = tls.get('utls') and tls.get('utls', {}).get('fingerprint')
        allow_insecure = tls.get('insecure') or tls.get('allow_insecure')
        transport = out.get('transport') or {}
        ttype = (transport.get('type') or '').lower()
        params = []
        params.append(f"security={security}")
        if sni:
            params.append(f"sni={quote(sni, safe='')}")
        if allow_insecure is True:
            params.append("allowInsecure=1")
        if alpn:
            if isinstance(alpn, list):
                params.append(f"alpn={quote(','.join(alpn), safe='')}")
            else:
                params.append(f"alpn={quote(str(alpn), safe='')}")
        if fp:
            params.append(f"fp={quote(fp, safe='')}")
        if ttype == 'ws':
            params.append("type=ws")
            ws_path = transport.get('path') or ''
            if ws_path:
                params.append(f"path={quote(ws_path, safe='')}")
            ws_headers = transport.get('headers') or {}
            ws_host = ws_headers.get('Host') or ws_headers.get('host')
            if ws_host:
                params.append(f"host={quote(ws_host, safe='')}")
        elif ttype == 'grpc':
            params.append("type=grpc")
            grpc_sn = transport.get('service_name') or transport.get('serviceName')
            if grpc_sn:
                params.append(f"serviceName={quote(grpc_sn, safe='')}")
        elif ttype == 'http' or ttype == 'h2':
            params.append("type=http")
            h_path = transport.get('path') or '/'
            if h_path:
                params.append(f"path={quote(h_path, safe='')}")
            h_host = (transport.get('headers') or {}).get('Host') or (transport.get('headers') or {}).get('host')
            if h_host:
                params.append(f"host={quote(h_host, safe='')}")
        tag = out.get('tag') or ''
        remark = remark_base
        if tag:
            remark = f"{remark_base} | {tag}"
        remark_clean = remark.replace('#', ' ').strip()
        qs = '&'.join(params)
        link = f"trojan://{quote(pwd, safe='')}@{server}:{sport}?{qs}#{quote(remark_clean, safe='')}"
        return link
    except Exception:
        return None
def build_vmess_link(out: Dict[str, Any], remark_base: str) -> Optional[str]:
    try:
        server = out.get('server')
        sport = out.get('server_port') or out.get('port')
        uuid = out.get('uuid')
        aid = out.get('alter_id') or out.get('alterId') or 0
        if not (server and sport and uuid):
            return None
        tls = out.get('tls') or {}
        security = 'tls' if tls.get('enabled') is True else 'none'
        sni = tls.get('server_name') or tls.get('sni') or server
        transport = out.get('transport') or {}
        ttype = (transport.get('type') or 'tcp').lower()
        net = ttype
        vmess_obj = {
            "v": "2",
            "ps": remark_base.replace('#', ' ').strip(),
            "add": server,
            "port": str(sport),
            "id": uuid,
            "aid": str(aid),
            "scy": "auto",
            "net": net,
            "type": "none",
            "host": "",
            "path": "",
            "tls": security if security == 'tls' else ""
        }
        if ttype == 'ws':
            ws_path = transport.get('path') or ''
            ws_headers = transport.get('headers') or {}
            ws_host = ws_headers.get('Host') or ws_headers.get('host') or ''
            vmess_obj["path"] = ws_path
            vmess_obj["host"] = ws_host
        elif ttype == 'grpc':
            grpc_sn = transport.get('service_name') or transport.get('serviceName') or ''
            vmess_obj["path"] = grpc_sn
            vmess_obj["net"] = 'grpc'
        elif ttype == 'http' or ttype == 'h2':
            h_path = transport.get('path') or '/'
            h_host = (transport.get('headers') or {}).get('Host') or (transport.get('headers') or {}).get('host') or ''
            vmess_obj["path"] = h_path
            vmess_obj["host"] = h_host
            vmess_obj["net"] = 'http'
        if security == 'tls' and sni:
            vmess_obj["sni"] = sni
        import base64
        jstr = json.dumps(vmess_obj, separators=(',', ':'), ensure_ascii=False)
        b64 = base64.b64encode(jstr.encode('utf-8')).decode('ascii')
        return f"vmess://{b64}"
    except Exception:
        return None


def build_ss_link(out: Dict[str, Any], remark_base: str) -> Optional[str]:
    try:
        server = out.get('server')
        sport = out.get('server_port') or out.get('port')
        method = out.get('method')
        pwd = out.get('password')
        if not (server and sport and method and pwd):
            return None
        import base64
        userinfo = f"{method}:{pwd}"
        b64ui = base64.b64encode(userinfo.encode('utf-8')).decode('ascii').rstrip('=')
        tag = out.get('tag') or ''
        remark = remark_base
        if tag:
            remark = f"{remark_base} | {tag}"
        remark_clean = remark.replace('#', ' ').strip()
        return f"ss://{b64ui}@{server}:{sport}#{quote(remark_clean, safe='')}"
    except Exception:
        return None
def extract_remark_base(source_name: str, url_or_path: str) -> str:
    base = source_name
    m = re.search(r'(admin\d+[A-Za-z0-9_-]+|user\s*\d+|пользователь\s*\d+)', base, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'(admin\d+)', base, re.IGNORECASE)
    if m:
        return m.group(1)
    nm = re.sub(r'\.json$', '', base, flags=re.IGNORECASE)
    nm = re.sub(r'-(TRJ|VLESS|TROJAN|CLIENT)$', '', nm, flags=re.IGNORECASE)
    if nm:
        return nm
    p = urlparse(url_or_path)
    return p.netloc or 'profile'


def convert_one(url_or_path: str, timeout: int) -> Dict[str, Any]:
    res = {
        'input': url_or_path,
        'ok': False,
        'error': None,
        'source': '',
        'remark_base': '',
        'vless': [],
        'trojan': [],
        'vmess': [],
        'ss': [],
        'count_total': 0
    }
    data, err, src = load_local_or_remote(url_or_path, timeout)
    res['source'] = src
    if err or not isinstance(data, dict):
        res['error'] = err or 'Not a JSON object'
        return res
    rbase = extract_remark_base(src, url_or_path)
    res['remark_base'] = rbase
    outbounds = data.get('outbounds') or []
    if not isinstance(outbounds, list):
        outbounds = []
    res['count_total'] = len(outbounds)
    for o in outbounds:
        if not isinstance(o, dict):
            continue
        otype = (o.get('type') or '').lower().strip()
        if otype == 'vless':
            l = build_vless_link(o, rbase)
            if l:
                res['vless'].append(l)
        elif otype == 'trojan':
            l = build_trojan_link(o, rbase)
            if l:
                res['trojan'].append(l)
        elif otype == 'vmess':
            l = build_vmess_link(o, rbase)
            if l:
                res['vmess'].append(l)
        elif otype == 'shadowsocks' or otype == 'ss':
            l = build_ss_link(o, rbase)
            if l:
                res['ss'].append(l)
    res['ok'] = (len(res['vless']) + len(res['trojan']) + len(res['vmess']) + len(res['ss'])) > 0
    if not res['ok'] and res['error'] is None:
        res['error'] = 'No supported outbounds (vless/trojan/vmess/ss) found'
    return res
def main():
    ap = argparse.ArgumentParser(description='Универсальный конвертер sing-box (JSON) -> share-ссылки vless:// trojan:// vmess:// ss://')
    ap.add_argument('input', help='Файл .txt с ссылками на .json ИЛИ один .json файл/URL')
    ap.add_argument('-o', '--output', default=None, help='Выходной файл (по умолчанию печатает в stdout)')
    ap.add_argument('--by-users', action='store_true', help='Группировать ссылки по пользователям (remark_base)')
    ap.add_argument('--no-sort', action='store_true', help='Не сортировать')
    ap.add_argument('--timeout', type=int, default=20, help='Таймаут HTTP (сек), по умолчанию 20')
    ap.add_argument('--workers', type=int, default=4, help='Параллельных загрузок, по умолчанию 4')
    args = ap.parse_args()

    inp = args.input
    candidates: List[str] = []
    if os.path.exists(inp) and os.path.isfile(inp):
        try:
            with open(inp, 'r', encoding='utf-8', errors='replace') as f:
                txt = f.read()
        except Exception:
            txt = ''
        urls_found = extract_json_urls(txt)
        if len(urls_found) > 0:
            candidates = urls_found
        else:
            candidates = [inp]
    else:
        p = urlparse(inp)
        if p.scheme in ('http', 'https'):
            candidates = [inp]
        else:
            print(f'Файл/URL не найден: {inp}', file=sys.stderr)
            sys.exit(1)

    results: List[Dict[str, Any]] = []
    if len(candidates) == 1:
        results.append(convert_one(candidates[0], args.timeout))
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = [ex.submit(convert_one, u, args.timeout) for u in candidates]
            for f in as_completed(futs):
                try:
                    results.append(f.result())
                except Exception as e:
                    results.append({
                        'input': '<unknown>', 'ok': False, 'error': str(e),
                        'source': '', 'remark_base': '', 'vless': [], 'trojan': [], 'vmess': [], 'ss': [], 'count_total': 0
                    })

    if not args.no_sort:
        results.sort(key=lambda x: (x.get('remark_base') or x.get('source') or ''))

    lines: List[str] = []
    lines.append(f"# Sing-box → Share Links")
    lines.append(f"# Сгенерировано: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    if args.by_users:
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for r in results:
            k = r.get('remark_base') or r.get('source') or 'unknown'
            groups.setdefault(k, []).append(r)
        for gk in sorted(groups.keys()):
            gr = groups[gk]
            lines.append(f"## {gk}")
            lines.append("")
            for r in gr:
                src = r.get('source') or ''
                inp = r.get('input') or ''
                if src:
                    lines.append(f"### {src}")
                for lnk in r.get('vless', []):
                    lines.append(lnk)
                for lnk in r.get('trojan', []):
                    lines.append(lnk)
                for lnk in r.get('vmess', []):
                    lines.append(lnk)
                for lnk in r.get('ss', []):
                    lines.append(lnk)
                if not r.get('ok'):
                    lines.append(f"# ERROR: {r.get('error')} ({inp})")
                lines.append("")
            lines.append("")
    else:
        for r in results:
            src = r.get('source') or ''
            inp = r.get('input') or ''
            rbase = r.get('remark_base') or ''
            title = f"{rbase} — {src}" if (rbase and src) else (rbase or src or inp)
            lines.append(f"## {title}")
            lines.append("")
            for lnk in r.get('vless', []):
                lines.append(lnk)
            for lnk in r.get('trojan', []):
                lines.append(lnk)
            for lnk in r.get('vmess', []):
                lines.append(lnk)
            for lnk in r.get('ss', []):
                lines.append(lnk)
            if not r.get('ok'):
                lines.append(f"# ERROR: {r.get('error')} ({inp})")
            lines.append("")

    errs = [r for r in results if not r.get('ok')]
    if errs:
        lines.append("## ERRORS")
        lines.append("")
        for e in errs:
            lines.append(f"- {e.get('input')}: {e.get('error')}")
        lines.append("")

    out_text = '\n'.join(lines).rstrip() + '\n'

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(out_text)
            print(f'Готово: {args.output}')
        except Exception as e:
            print(f'Не удалось записать {args.output}: {e}', file=sys.stderr)
            sys.stdout.write(out_text)
    else:
        sys.stdout.write(out_text)


if __name__ == '__main__':
    main()
