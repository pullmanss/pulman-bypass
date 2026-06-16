# Pulman Bypass

Программа для обхода блокировок YouTube, Discord, ChatGPT и других сайтов. Объединяет все способы обхода в одном окне — без настроек и командной строки.

## Возможности

- 🛡 **Zapret (DPI Bypass)** — обход блокировок YouTube и Discord без VPN через WinDivert. 21 пресет на выбор.
- 🌐 **VPN клиент (Sing-Box)** — встроенный VPN с поддержкой VLESS, VMESS, Shadowsocks. ~150 бесплатных серверов с автообновлением.
- 💬 **Telegram Proxy** — WebSocket прокси для Telegram одной кнопкой.
- 📊 **Проверка доступности** — статус YouTube, ChatGPT, Discord, SoundCloud прямо в приложении.

## Установка

1. Скачайте `pulman-bypass.exe` из [Releases](../../releases)
2. Запустите от имени администратора
3. При первом запуске программа автоматически скачает необходимые компоненты

## Системные требования

- Windows 10/11 (64-bit)
- Права администратора (для Zapret/WinDivert)

## Сборка из исходников

```bash
pip install -r requirements.txt
python main.py
```

### Сборка EXE

```bash
pip install pyinstaller
pyinstaller pulman-bypass.spec --clean
```

## Технологии

- Python 3.14 + PyQt6
- [Zapret](https://github.com/flowseal/zapret-discord-youtube) — DPI bypass
- [Sing-Box](https://github.com/SagerNet/sing-box) — VPN ядро
- Портабельное, без установки

## Лицензия

MIT
