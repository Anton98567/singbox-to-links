#!/usr/bin/env bash
# singbox-to-links — одна команда с GitHub:
#   curl -fsSL https://raw.githubusercontent.com/Anton98567/singbox-to-links/main/run.sh | bash
# Файл со ссылками (по умолчанию configs.txt) можно указать вторым аргументом:
#   curl -fsSL .../run.sh | bash -s -- мой_файл.txt
set -euo pipefail

PY_URL="https://raw.githubusercontent.com/Anton98567/singbox-to-links/main/singbox_to_links.py"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Не найден python3. Установите его (apt install python3 / yum install python3)" >&2
    exit 1
fi

curl -fsSL "$PY_URL" | python3 - "$@"
