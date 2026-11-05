#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
singbox-to-links — sing-box JSON конфиги -> готовые share-ссылки.

Быстрый старт (одна команда):
    python3 singbox_to_links.py

Скрипт читает configs.txt (ссылки на .json-конфиги; можно вставлять целым
блоком с любым посторонним текстом — IP, портами, паролями, подписями),
выцепляет из него ссылки/файлы *.json и пишет:

    links.txt — готовые share-ссылки, по одной на строку
    links.md  — отчёт, сгруппированный по пользователям
    sub.txt   — base64-подписка для импорта в клиенты

Ссылки также печатаются в терминал.
"""
import argparse
import base64
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

try:
    import requests
except ImportError:
    print("Требуется библиотека requests. Установи: pip install requests", file=sys.stderr)
    sys.exit(1)

USER_AGENT = 'singbox-to-links/2.0'
DEFAULT_INPUT = 'configs.txt'

# Ссылка вида https://host/.../имя.json (с query-строкой) ИЛИ локальный путь к *.json
ANY_JSON_RE = re.compile(
    r'https?://[^\s\'"<>()\[\]{}]+?\.json[^\s\'"<>()\[\]{}]*'
    r'|(?<![\w])[~./\w\-]+\.json\b',
    re.IGNORECASE,
)
TRAILING_PUNCT = re.compile(r'[\)\]\},;\'"]+$')
SUFFIX_RE = re.compile(
    r'-(TRJ|VLESS|TROJAN|VMESS|SS|HY2|HY1|TUIC|CLIENT|CONFIG|OUT|IN)$',
    re.IGNORECASE,
)

PROTO_LABEL = {
    'vless': 'VLESS',
    'trojan': 'TRJ',
    'vmess': 'VMESS',
    'shadowsocks': 'SS',
    'ss': 'SS',
    'hysteria2': 'HY2',
    'hysteria': 'HY1',
    'tuic': 'TUIC',
}

TEMPLATE = """# Сюда вставьте ссылки на .json-конфиги (можно целым блоком из тикета/панели).
# Весь посторонний текст (IP, порты, пароли, подписи) игнорируется:
# скрипт выцепляет только ссылки и файлы вида .../имя-XXX-CLIENT.json
#
# Пример:
# https://vpn.example.com/secretpath/r1-TRJ-CLIENT.json
# https://vpn.example.com/secretpath/r1-VLESS-CLIENT.json
#
# Затем запустите снова:
#   python3 singbox_to_links.py
"""


# ---------------------------------------------------------------- утилиты

def clean_url(u: str) -> str:
    return TRAILING_PUNCT.sub('', u).strip()


def resolve_local(tok: str, base_dir: str) -> Optional[str]:
    for cand in (tok, os.path.join(base_dir, tok)):
        p = os.path.expanduser(cand)
        if os.path.isfile(p):
            return os.path.abspath(p)
    return None


def extract_candidates(text: str, base_dir: str) -> List[str]:
    """Выцепляет из произвольного текста уникальные ссылки/пути на .json (в порядке появления)."""
    out: List[str] = []
    seen = set()
    for m in ANY_JSON_RE.finditer(text):
        tok = m.group(0)
        if tok.lower().startswith(('http://', 'https://')):
            cand = clean_url(tok)
        else:
            cand = resolve_local(tok, base_dir)
            if not cand:
                continue
        if cand and cand not in seen:
            seen.add(cand)
            out.append(cand)
    return out


def load_local_or_remote(url_or_path: str, timeout: int = 20):
    p = urlparse(url_or_path)
    if p.scheme in ('http', 'https'):
        try:
            r = requests.get(url_or_path, timeout=timeout, headers={'User-Agent': USER_AGENT})
            r.raise_for_status()
            try:
                data = r.json()
            except Exception:
                data = json.loads(r.text)
            fname = os.path.basename(p.path) or p.netloc
            return data, None, fname
        except requests.RequestException as e:
            return None, f"HTTP error: {e}", url_or_path
        except Exception as e:
            return None, f"JSON parse error: {e}", url_or_path
    try:
        with open(url_or_path, 'r', encoding='utf-8', errors='replace') as f:
            data = json.loads(f.read())
        return data, None, os.path.basename(url_or_path)
    except Exception as e:
        return None, f"File error: {e}", os.path.basename(url_or_path)


def extract_remark_base(source_name: str, url_or_path: str) -> str:
    """r1-TRJ-CLIENT.json -> r1; admin123x-CLIENT.json -> admin123x."""
    nm = re.sub(r'\.json$', '', source_name, flags=re.IGNORECASE)
    while True:
        stripped = SUFFIX_RE.sub('', nm)
        if stripped == nm:
            break
        nm = stripped
    m = re.search(r'(admin\d+[A-Za-z0-9_-]*|user[\s_-]?\d+|пользователь\s*\d+)', nm, re.IGNORECASE)
    if m:
        return m.group(1)
    if nm:
        return nm
    p = urlparse(url_or_path)
    return p.netloc or 'profile'


def _tls_bits(tls: Dict[str, Any]):
    security = 'tls' if tls.get('enabled') is True else 'none'
    sni = tls.get('server_name') or tls.get('sni')
    alpn = tls.get('alpn')
    if isinstance(alpn, list):
        alpn = ','.join(alpn)
    elif alpn is not None:
        alpn = str(alpn)
    fp = (tls.get('utls') or {}).get('fingerprint')
    insecure = bool(tls.get('insecure') or tls.get('allow_insecure'))
    return security, sni, alpn, fp, insecure


def _transport_params(transport: Dict[str, Any], params: List[str]) -> None:
    ttype = (transport.get('type') or '').lower()
    if ttype == 'ws':
        params.append("type=ws")
        path = transport.get('path') or ''
        if path:
            params.append(f"path={quote(path, safe='')}")
        headers = transport.get('headers') or {}
        host = headers.get('Host') or headers.get('host')
        if host:
            params.append(f"host={quote(host, safe='')}")
    elif ttype == 'grpc':
        params.append("type=grpc")
        sn = transport.get('service_name') or transport.get('serviceName')
        if sn:
            params.append(f"serviceName={quote(sn, safe='')}")
    elif ttype in ('http', 'h2'):
        params.append("type=http")
        path = transport.get('path') or '/'
        if path:
            params.append(f"path={quote(path, safe='')}")
        headers = transport.get('headers') or {}
        host = headers.get('Host') or headers.get('host')
        if host:
            params.append(f"host={quote(host, safe='')}")
    elif ttype == 'httpupgrade':
        params.append("type=httpupgrade")
        path = transport.get('path') or '/'
        if path:
            params.append(f"path={quote(path, safe='')}")
        headers = transport.get('headers') or {}
        host = headers.get('Host') or headers.get('host')
        if host:
            params.append(f"host={quote(host, safe='')}")
    elif ttype == 'wsupgrade':
        params.append("type=httpupgrade")
        path = transport.get('path') or '/'
        if path:
            params.append(f"path={quote(path, safe='')}")


def _server_port(out: Dict[str, Any]):
    return out.get('server_port') or out.get('port')


# ------------------------------------------------------------- билдеры ссылок

def build_vless_link(out: Dict[str, Any], remark: str) -> Optional[str]:
    try:
        server = out.get('server')
        sport = _server_port(out)
        uuid = out.get('uuid')
        if not (server and sport and uuid):
            return None
        tls = out.get('tls') or {}
        security, sni, alpn, fp, insecure = _tls_bits(tls)
        params = ["encryption=none", f"security={security}"]
        if sni:
            params.append(f"sni={quote(sni, safe='')}")
        if insecure:
            params.append("allowInsecure=1")
        if alpn:
            params.append(f"alpn={quote(alpn, safe='')}")
        if fp:
            params.append(f"fp={quote(fp, safe='')}")
        _transport_params(out.get('transport') or {}, params)
        flow = out.get('flow')
        if flow:
            params.append(f"flow={quote(flow, safe='')}")
        return f"vless://{uuid}@{server}:{sport}?{'&'.join(params)}#{quote(remark, safe='')}"
    except Exception:
        return None


def build_trojan_link(out: Dict[str, Any], remark: str) -> Optional[str]:
    try:
        server = out.get('server')
        sport = _server_port(out)
        pwd = out.get('password') or out.get('passwd')
        if not (server and sport and pwd):
            return None
        tls = out.get('tls') or {}
        security, sni, alpn, fp, insecure = _tls_bits(tls)
        params = [f"security={security}"]
        if sni:
            params.append(f"sni={quote(sni, safe='')}")
        if insecure:
            params.append("allowInsecure=1")
        if alpn:
            params.append(f"alpn={quote(alpn, safe='')}")
        if fp:
            params.append(f"fp={quote(fp, safe='')}")
        _transport_params(out.get('transport') or {}, params)
        return f"trojan://{quote(str(pwd), safe='')}@{server}:{sport}?{'&'.join(params)}#{quote(remark, safe='')}"
    except Exception:
        return None


def build_vmess_link(out: Dict[str, Any], remark: str) -> Optional[str]:
    try:
        server = out.get('server')
        sport = _server_port(out)
        uuid = out.get('uuid')
        aid = out.get('alter_id') or out.get('alterId') or 0
        if not (server and sport and uuid):
            return None
        tls = out.get('tls') or {}
        security, sni, _alpn, _fp, _insecure = _tls_bits(tls)
        transport = out.get('transport') or {}
        ttype = (transport.get('type') or 'tcp').lower()
        vmess_obj = {
            "v": "2",
            "ps": remark,
            "add": server,
            "port": str(sport),
            "id": uuid,
            "aid": str(aid),
            "scy": "auto",
            "net": ttype if ttype not in ('wsupgrade',) else 'httpupgrade',
            "type": "none",
            "host": "",
            "path": "",
            "tls": security if security == 'tls' else "",
        }
        if ttype == 'ws':
            headers = transport.get('headers') or {}
            vmess_obj["path"] = transport.get('path') or ''
            vmess_obj["host"] = headers.get('Host') or headers.get('host') or ''
        elif ttype == 'grpc':
            vmess_obj["path"] = transport.get('service_name') or transport.get('serviceName') or ''
            vmess_obj["net"] = 'grpc'
        elif ttype in ('http', 'h2'):
            headers = transport.get('headers') or {}
            vmess_obj["path"] = transport.get('path') or '/'
            vmess_obj["host"] = headers.get('Host') or headers.get('host') or ''
            vmess_obj["net"] = 'http'
        if security == 'tls' and sni:
            vmess_obj["sni"] = sni
        jstr = json.dumps(vmess_obj, separators=(',', ':'), ensure_ascii=False)
        return "vmess://" + base64.b64encode(jstr.encode('utf-8')).decode('ascii')
    except Exception:
        return None


def build_ss_link(out: Dict[str, Any], remark: str) -> Optional[str]:
    try:
        server = out.get('server')
        sport = _server_port(out)
        method = out.get('method')
        pwd = out.get('password')
        if not (server and sport and method and pwd):
            return None
        userinfo = f"{method}:{pwd}"
        b64ui = base64.b64encode(userinfo.encode('utf-8')).decode('ascii').rstrip('=')
        return f"ss://{b64ui}@{server}:{sport}#{quote(remark, safe='')}"
    except Exception:
        return None


def build_hysteria2_link(out: Dict[str, Any], remark: str) -> Optional[str]:
    try:
        server = out.get('server')
        sport = _server_port(out)
        pwd = out.get('password') or out.get('auth') or out.get('auth_str')
        if not (server and sport and pwd):
            return None
        tls = out.get('tls') or {}
        _security, sni, alpn, _fp, insecure = _tls_bits(tls)
        params = []
        if sni:
            params.append(f"sni={quote(sni, safe='')}")
        if insecure:
            params.append("insecure=1")
        if alpn:
            params.append(f"alpn={quote(alpn, safe='')}")
        obfs = out.get('obfs') or {}
        if obfs.get('type'):
            params.append(f"obfs={quote(str(obfs['type']), safe='')}")
            if obfs.get('password'):
                params.append(f"obfs-password={quote(str(obfs['password']), safe='')}")
        qs = ('?' + '&'.join(params)) if params else ''
        return f"hysteria2://{quote(str(pwd), safe='')}@{server}:{sport}{qs}#{quote(remark, safe='')}"
    except Exception:
        return None


def build_tuic_link(out: Dict[str, Any], remark: str) -> Optional[str]:
    try:
        server = out.get('server')
        sport = _server_port(out)
        uuid = out.get('uuid')
        pwd = out.get('password')
        if not (server and sport and uuid and pwd):
            return None
        tls = out.get('tls') or {}
        _security, sni, alpn, _fp, insecure = _tls_bits(tls)
        params = []
        cc = out.get('congestion_control') or 'bbr'
        mode = out.get('udp_relay_mode') or 'native'
        params.append(f"congestion_control={quote(str(cc), safe='')}")
        params.append(f"udp_relay_mode={quote(str(mode), safe='')}")
        params.append(f"alpn={quote(alpn or 'h3', safe='')}")
        if sni:
            params.append(f"sni={quote(sni, safe='')}")
        if insecure:
            params.append("allowInsecure=1")
        return f"tuic://{quote(str(uuid), safe='')}:{quote(str(pwd), safe='')}@{server}:{sport}?{'&'.join(params)}#{quote(remark, safe='')}"
    except Exception:
        return None


def build_hysteria_link(out: Dict[str, Any], remark: str) -> Optional[str]:
    try:
        server = out.get('server')
        sport = _server_port(out)
        auth = out.get('auth_str') or out.get('auth') or out.get('password')
        if not (server and sport and auth):
            return None
        tls = out.get('tls') or {}
        _security, sni, alpn, _fp, insecure = _tls_bits(tls)
        params = [f"auth={quote(str(auth), safe='')}"]
        if sni:
            params.append(f"peer={quote(sni, safe='')}")
        if insecure:
            params.append("insecure=1")
        if alpn:
            params.append(f"alpn={quote(alpn, safe='')}")
        if out.get('up_mbps'):
            params.append(f"upmbps={int(out['up_mbps'])}")
        if out.get('down_mbps'):
            params.append(f"downmbps={int(out['down_mbps'])}")
        return f"hysteria://{server}:{sport}?{'&'.join(params)}#{quote(remark, safe='')}"
    except Exception:
        return None


BUILDERS = {
    'vless': build_vless_link,
    'trojan': build_trojan_link,
    'vmess': build_vmess_link,
    'shadowsocks': build_ss_link,
    'ss': build_ss_link,
    'hysteria2': build_hysteria2_link,
    'tuic': build_tuic_link,
    'hysteria': build_hysteria_link,
}


# ---------------------------------------------------------------- конвертация

def convert_one(url_or_path: str, timeout: int) -> Dict[str, Any]:
    res: Dict[str, Any] = {
        'input': url_or_path,
        'ok': False,
        'error': None,
        'source': '',
        'base': '',
        'links': [],
        'count_total': 0,
    }
    data, err, src = load_local_or_remote(url_or_path, timeout)
    res['source'] = src
    if err or not isinstance(data, (dict, list)):
        res['error'] = err or 'Not a JSON object'
        return res
    base = extract_remark_base(src, url_or_path)
    res['base'] = base
    if isinstance(data, dict):
        outbounds = data.get('outbounds') or []
    else:
        outbounds = data
    if not isinstance(outbounds, list):
        outbounds = []
    res['count_total'] = len(outbounds)
    for o in outbounds:
        if not isinstance(o, dict):
            continue
        otype = (o.get('type') or '').lower().strip()
        builder = BUILDERS.get(otype)
        if not builder:
            continue
        label = PROTO_LABEL.get(otype, otype.upper())
        link = builder(o, f"{base}-{label}")
        if link:
            res['links'].append({'proto': otype, 'remark': f"{base}-{label}", 'link': link})
    res['ok'] = len(res['links']) > 0
    if not res['ok'] and res['error'] is None:
        res['error'] = 'No supported outbounds (vless/trojan/vmess/ss/hysteria2/tuic/hysteria) found'
    return res


def finalize_remarks(links: List[Dict[str, Any]]) -> None:
    """Уникализирует комментарии: r1-TRJ, r1-TRJ-2, r1-TRJ-3... (и переписывает #fragment в ссылке)."""
    seen: Dict[str, int] = {}
    for it in links:
        r = it['remark']
        n = seen.get(r, 0) + 1
        seen[r] = n
        if n > 1:
            it['remark'] = f"{r}-{n}"
            it['link'] = it['link'].rsplit('#', 1)[0] + '#' + quote(it['remark'], safe='')


# ------------------------------------------------------------------- вывод

def build_report(results: List[Dict[str, Any]], flat_links: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    lines.append("# Sing-box → Share Links")
    lines.append(f"# Сгенерировано: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    groups: Dict[str, List[Dict[str, Any]]] = {}
    order: List[str] = []
    for r in results:
        k = r.get('base') or r.get('source') or 'unknown'
        if k not in groups:
            groups[k] = []
            order.append(k)
        for it in r.get('links', []):
            groups[k].append(it)
    for k in order:
        lines.append(f"## {k}")
        lines.append("")
        for it in groups[k]:
            lines.append(it['link'])
        lines.append("")
    errs = [r for r in results if not r.get('ok')]
    if errs:
        lines.append("## ERRORS")
        lines.append("")
        for e in errs:
            lines.append(f"- {e.get('input')}: {e.get('error')}")
        lines.append("")
    return '\n'.join(lines).rstrip() + '\n'


def write_file(path: str, text: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


# --------------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(
        description='sing-box JSON конфиги -> share-ссылки (vless:// trojan:// vmess:// ss:// hysteria2:// tuic:// hysteria://). '
                    'Без аргументов читает configs.txt и пишет links.txt / links.md / sub.txt.')
    ap.add_argument('input', nargs='?', default=DEFAULT_INPUT,
                    help=f'Файл со ссылками на .json (по умолчанию {DEFAULT_INPUT}) или один .json файл/URL')
    ap.add_argument('-o', '--output', default=None, help='Куда писать отчёт (по умолчанию links.md)')
    ap.add_argument('--quiet', action='store_true', help='Не печатать ссылки в терминал (только сводка)')
    ap.add_argument('--sort', action='store_true', help='Сортировать по именам пользователей (по умолчанию — порядок ввода)')
    ap.add_argument('--timeout', type=int, default=20, help='Таймаут HTTP (сек), по умолчанию 20')
    ap.add_argument('--workers', type=int, default=4, help='Параллельных загрузок, по умолчанию 4')
    # устаревшие флаги (оставлены для совместимости)
    ap.add_argument('--by-users', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--no-sort', action='store_true', help=argparse.SUPPRESS)
    args = ap.parse_args()

    inp = args.input
    base_dir = os.getcwd()
    candidates: List[str] = []

    if os.path.isfile(inp):
        base_dir = os.path.dirname(os.path.abspath(inp))
        try:
            with open(inp, 'r', encoding='utf-8', errors='replace') as f:
                txt = f.read()
        except Exception:
            txt = ''
        candidates = extract_candidates(txt, base_dir)
        if not candidates and inp.lower().endswith('.json'):
            candidates = [os.path.abspath(inp)]
        if not candidates:
            print(f'В файле не найдено ни одной ссылки или файла *.json: {inp}', file=sys.stderr)
            sys.exit(1)
    elif os.path.isdir(inp):
        print(f'Это папка, а не файл: {inp}', file=sys.stderr)
        sys.exit(1)
    else:
        p = urlparse(inp)
        if p.scheme in ('http', 'https'):
            candidates = [inp]
        elif inp.lower().endswith(('.txt', '.list', '.md')):
            # первого запуска ещё не было — создаём шаблон с подсказкой
            try:
                write_file(inp, TEMPLATE)
                print(f'Создан файл {inp} — вставьте в него ссылки на .json-конфиги и запустите:')
                print('  python3 singbox_to_links.py')
                sys.exit(0)
            except Exception as e:
                print(f'Не удалось создать {inp}: {e}', file=sys.stderr)
                sys.exit(1)
        else:
            print(f'Файл/URL не найден: {inp}', file=sys.stderr)
            sys.exit(1)

    # загрузка и конвертация (параллельно при нескольких источниках)
    if len(candidates) == 1:
        results = [convert_one(candidates[0], args.timeout)]
    else:
        results = []
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(convert_one, u, args.timeout): i for i, u in enumerate(candidates)}
            slot: List[Optional[Dict[str, Any]]] = [None] * len(candidates)
            for f in as_completed(futs):
                i = futs[f]
                try:
                    slot[i] = f.result()
                except Exception as e:
                    slot[i] = {
                        'input': candidates[i], 'ok': False, 'error': str(e),
                        'source': '', 'base': '', 'links': [], 'count_total': 0,
                    }
            results = [r for r in slot if r is not None]

    if args.sort:
        results.sort(key=lambda x: (x.get('base') or x.get('source') or ''))

    flat_links: List[Dict[str, Any]] = []
    for r in results:
        flat_links.extend(r.get('links', []))
    finalize_remarks(flat_links)

    out_dir = base_dir
    links_path = os.path.join(out_dir, 'links.txt')
    sub_path = os.path.join(out_dir, 'sub.txt')
    report_path = args.output or os.path.join(out_dir, 'links.md')

    flat_text = ''.join(it['link'] + '\n' for it in flat_links)
    try:
        write_file(links_path, flat_text)
        write_file(sub_path, base64.b64encode(flat_text.rstrip('\n').encode('utf-8')).decode('ascii') + '\n')
        write_file(report_path, build_report(results, flat_links))
    except Exception as e:
        print(f'Не удалось записать выходные файлы: {e}', file=sys.stderr)

    # сводка + ссылки в терминал
    ok_n = sum(1 for r in results if r.get('ok'))
    err_n = len(results) - ok_n
    print(f"Источников: {len(results)} (успешно: {ok_n}, ошибок: {err_n})  |  ссылок: {len(flat_links)}")
    if err_n:
        for r in results:
            if not r.get('ok'):
                print(f"  ! {r.get('input')}: {r.get('error')}", file=sys.stderr)
    if flat_links and not args.quiet:
        print()
        for it in flat_links:
            print(it['link'])
    print()
    print(f"Готово: {links_path}")
    print(f"        {report_path}")
    print(f"        {sub_path}")
    sys.exit(0 if flat_links else 1)


if __name__ == '__main__':
    main()
