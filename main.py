import sys
import os
import ctypes
import traceback

def get_project_dir():
    """For frozen EXE, use a hidden AppData folder so the user only sees the EXE."""
    if getattr(sys, 'frozen', False):
        appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
        data_dir = os.path.join(appdata, 'pulman-bypass')
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        return data_dir
    return os.path.dirname(os.path.abspath(__file__))

def get_resource_dir():
    """Where PyInstaller extracts bundled files (sys._MEIPASS for frozen)."""
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))

def extract_bundled_resources():
    """On first run, copy bundled bin/ and defaults from _MEIPASS to AppData."""
    if not getattr(sys, 'frozen', False):
        return
    
    import shutil
    resource_dir = get_resource_dir()
    project_dir = get_project_dir()
    
    # Extract bin/ folder if missing
    bundled_bin = os.path.join(resource_dir, "bin")
    target_bin = os.path.join(project_dir, "bin")
    if os.path.exists(bundled_bin) and not os.path.exists(target_bin):
        shutil.copytree(bundled_bin, target_bin)
    
    # Extract default vpn_keys.json if missing
    bundled_keys = os.path.join(resource_dir, "vpn_keys.json")
    target_keys = os.path.join(project_dir, "vpn_keys.json")
    if os.path.exists(bundled_keys) and not os.path.exists(target_keys):
        shutil.copy2(bundled_keys, target_keys)

    # Extract app_icon.ico if missing
    bundled_icon = os.path.join(resource_dir, "app_icon.ico")
    target_icon = os.path.join(project_dir, "app_icon.ico")
    if os.path.exists(bundled_icon) and not os.path.exists(target_icon):
        shutil.copy2(bundled_icon, target_icon)

# Setup crash logging at the absolute top-level
def log_crash(e):
    try:
        log_path = os.path.join(get_project_dir(), "crash.log")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"Top-level Exception: {str(e)}\n")
            traceback.print_exc(file=f)
    except Exception:
        pass

try:
    import shutil
    import urllib.request
    import urllib.parse
    import json
    import base64
    import zipfile
    import subprocess
    import threading
    import time
    import psutil
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
        QLabel, QLineEdit, QPushButton, QComboBox, QPlainTextEdit, 
        QProgressBar, QSizePolicy, QDialog, QAbstractButton, QFrame,
        QGraphicsDropShadowEffect, QScrollArea, QFileDialog, QGridLayout,
        QGraphicsOpacityEffect, QListWidget
    )
    from PyQt6.QtCore import QThread, pyqtSignal, Qt, QPropertyAnimation, pyqtProperty, QSize, QEasingCurve, QTimer, QRectF
    from PyQt6.QtGui import QPainter, QColor, QBrush, QPen, QFont, QIcon, QLinearGradient, QRadialGradient

    # -----------------------------------------------------------------------------
    # UAC Elevation & Admin Check
    # -----------------------------------------------------------------------------
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    def run_as_admin():
        if not is_admin():
            if getattr(sys, 'frozen', False):
                cmd = sys.executable
                params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            else:
                cmd = sys.executable
                script = os.path.abspath(sys.argv[0])
                params = f'"{script}" ' + ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
                
            work_dir = get_project_dir()
            try:
                ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", cmd, params, work_dir, 1)
                if int(ret) > 32:
                    sys.exit(0)
                else:
                    log_crash(f"UAC elevation refused or failed: return code {ret}")
                    sys.exit(1)
            except Exception as e:
                log_crash(e)
                sys.exit(1)

    # UAC elevation will be triggered under __main__ block to prevent side effects on import.
except Exception as e:
    raise

# -----------------------------------------------------------------------------
# Base64 and Key Parsers (Shadowsocks, VLESS, VMESS)
# -----------------------------------------------------------------------------
def parse_base64(s):
    s = s.strip()
    # Add proper base64 padding if missing
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return None

def parse_vpn_key(key_str):
    key_str = key_str.strip()
    if not (key_str.startswith('ss://') or key_str.startswith('vless://') or key_str.startswith('vmess://')):
        raise ValueError("Неподдерживаемый протокол. Поддерживаются только ss://, vless:// и vmess://")

    # Handle VMESS key
    if key_str.startswith('vmess://'):
        base64_part = key_str[8:]
        decoded = parse_base64(base64_part)
        if not decoded:
            raise ValueError("Ошибка декодирования VMESS Base64")
        try:
            data = json.loads(decoded)
            return {
                'type': 'vmess',
                'host': data.get('add', ''),
                'port': int(data.get('port', 443)),
                'uuid': data.get('id', ''),
                'aid': int(data.get('aid', 0)),
                'net': data.get('net', 'tcp'),
                'type_header': data.get('type', 'none'),
                'path': data.get('path', ''),
                'sni': data.get('sni', ''),
                'tls': data.get('tls', ''),
                'tag': data.get('ps', 'VMESS Server')
            }
        except Exception as e:
            raise ValueError(f"Ошибка парсинга JSON в VMESS ключе: {str(e)}")

    parsed_url = urllib.parse.urlparse(key_str)
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc
    tag = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else "VPN Server"

    if scheme == 'ss':
        # ss://BASE64_USERINFO@HOST:PORT
        if '@' in netloc:
            userinfo_b64, host_port = netloc.split('@', 1)
            decoded_userinfo = parse_base64(userinfo_b64)
            if decoded_userinfo and ':' in decoded_userinfo:
                method, password = decoded_userinfo.split(':', 1)
            else:
                if ':' in userinfo_b64:
                    method, password = userinfo_b64.split(':', 1)
                else:
                    raise ValueError("Неверный формат Shadowsocks userinfo")
        else:
            # Whole netloc is base64
            decoded = parse_base64(netloc)
            if decoded and '@' in decoded:
                userinfo, host_port = decoded.split('@', 1)
                if ':' in userinfo:
                    method, password = userinfo.split(':', 1)
                else:
                    raise ValueError("Неверный формат Shadowsocks userinfo в base64")
            else:
                raise ValueError("Неверная base64 кодировка Shadowsocks ключа")

        if ':' in host_port:
            host, port = host_port.split(':', 1)
            port = int(port)
        else:
            host = host_port
            port = 443

        return {
            'type': 'shadowsocks',
            'host': host,
            'port': port,
            'method': method,
            'password': password,
            'tag': tag
        }

    elif scheme == 'vless':
        if '@' not in netloc:
            raise ValueError("Неверный формат VLESS (отсутствует UUID)")
        uuid, host_port = netloc.split('@', 1)
        if ':' in host_port:
            host, port = host_port.split(':', 1)
            port = int(port)
        else:
            host = host_port
            port = 443

        query_params = urllib.parse.parse_qs(parsed_url.query)
        security = query_params.get('security', ['none'])[0]
        network = query_params.get('type', ['tcp'])[0]
        sni = query_params.get('sni', [''])[0]
        fp = query_params.get('fp', [''])[0]
        pbk = query_params.get('pbk', [''])[0]
        sid = query_params.get('sid', [''])[0]
        flow = query_params.get('flow', [''])[0]
        path = query_params.get('path', [''])[0]

        return {
            'type': 'vless',
            'uuid': uuid,
            'host': host,
            'port': port,
            'security': security,
            'network': network,
            'sni': sni,
            'fp': fp,
            'pbk': pbk,
            'sid': sid,
            'flow': flow,
            'path': path,
            'tag': tag
        }

def fetch_subscription(url, retries=3):
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Try multiple User-Agents — subscription servers return different formats per client.
    # v2rayN / Shadowrocket UAs get proper base64 vless:// lists.
    user_agents = [
        'v2rayN/6.22',
        'Shadowrocket/1900',
        'clash-verge/v1.7.2',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    ]

    content = None
    last_error = None
    for ua in user_agents:
        for attempt in range(1, retries + 1):
            try:
                req = urllib.request.Request(url, headers={
                    'User-Agent': ua,
                    'Accept': '*/*',
                })
                with urllib.request.urlopen(req, timeout=20, context=ctx) as response:
                    content = response.read()
                break
            except Exception as e:
                last_error = e
                if attempt < retries:
                    time.sleep(1)
        if content is not None:
            break

    if content is None:
        raise last_error

    # --- Try standard base64 list (vless://, vmess://, ss://) ---
    servers = []
    try:
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        for line in decoded.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                srv = parse_vpn_key(line)
                if srv:
                    servers.append(srv)
            except Exception:
                pass
    except Exception:
        pass

    if servers:
        return servers

    # --- Fallback: try raw text (non-base64) ---
    raw = content.decode('utf-8', errors='ignore')
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            srv = parse_vpn_key(line)
            if srv:
                servers.append(srv)
        except Exception:
            pass

    if servers:
        return servers

    # --- Fallback: Clash YAML format ---
    servers = _parse_clash_yaml(raw)
    return servers


def _parse_clash_yaml(yaml_text):
    """Extract servers from Clash YAML proxies section without pyyaml dependency."""
    servers = []
    in_proxies = False
    current_proxy = {}

    for line in yaml_text.splitlines():
        stripped = line.strip()

        if stripped == 'proxies:':
            in_proxies = True
            continue

        if not in_proxies:
            continue

        # End of proxies block
        if stripped and not line.startswith(' ') and not line.startswith('-') and stripped != 'proxies:':
            break

        # New proxy entry
        if stripped.startswith('- ') and ('name:' in stripped or 'type:' in stripped):
            if current_proxy:
                srv = _clash_proxy_to_server(current_proxy)
                if srv:
                    servers.append(srv)
            current_proxy = {}
            stripped = stripped[2:]  # Remove "- "

        # Parse key: value pairs
        if ':' in stripped and not stripped.startswith('#'):
            key, _, val = stripped.partition(':')
            current_proxy[key.strip()] = val.strip()

    if current_proxy:
        srv = _clash_proxy_to_server(current_proxy)
        if srv:
            servers.append(srv)

    return servers


def _clash_proxy_to_server(p):
    """Convert a Clash proxy dict to our internal server format."""
    try:
        proxy_type = p.get('type', '').lower()
        host = p.get('server', '')
        port = int(p.get('port', 443))
        name = p.get('name', f'{host}:{port}')

        if proxy_type == 'ss':
            return {
                'type': 'shadowsocks',
                'host': host, 'port': port,
                'method': p.get('cipher', 'aes-256-gcm'),
                'password': p.get('password', ''),
                'tag': name
            }
        elif proxy_type == 'vless':
            return {
                'type': 'vless',
                'host': host, 'port': port,
                'uuid': p.get('uuid', ''),
                'security': p.get('tls', False) and 'tls' or 'none',
                'network': p.get('network', 'tcp'),
                'sni': p.get('servername', ''),
                'fp': p.get('client-fingerprint', ''),
                'pbk': '', 'sid': '', 'flow': p.get('flow', ''),
                'path': p.get('ws-opts', {}).get('path', '') if isinstance(p.get('ws-opts'), dict) else '',
                'tag': name
            }
        elif proxy_type == 'vmess':
            return {
                'type': 'vmess',
                'host': host, 'port': port,
                'uuid': p.get('uuid', ''),
                'aid': int(p.get('alterId', 0)),
                'net': p.get('network', 'tcp'),
                'type_header': 'none',
                'path': '',
                'sni': p.get('servername', ''),
                'tls': 'tls' if p.get('tls') else '',
                'tag': name
            }
    except Exception:
        pass
    return None

# -----------------------------------------------------------------------------
# QSS Stylesheet (Monochrome Liquid Glass)
# -----------------------------------------------------------------------------
CATPPUCCIN_STYLE = """
QMainWindow {
    background-color: #050508;
}

QDialog {
    background-color: #050508;
}

/* Base text styles */
QLabel {
    color: #e4e4e7;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}

QLabel#main-title {
    font-size: 24px;
    font-weight: 900;
    color: #ffffff;
    letter-spacing: 2px;
}

QLabel#main-subtitle {
    font-size: 12px;
    color: #a1a1aa;
}

QLabel#card-title {
    font-size: 15px;
    font-weight: 700;
    color: #ffffff;
}

QLabel#card-description {
    font-size: 11px;
    color: #71717a;
}

/* Inputs with glassmorphism */
QLineEdit {
    background-color: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 10px;
    color: #ffffff;
    padding: 8px 12px;
    font-size: 13px;
    font-family: "Segoe UI", "Inter", sans-serif;
}

QLineEdit:focus {
    background-color: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.3);
}

/* Dropdowns with glassmorphism */
QComboBox {
    background-color: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 10px;
    color: #ffffff;
    padding: 8px 12px;
    font-size: 13px;
    font-family: "Segoe UI", "Inter", sans-serif;
}

QComboBox:hover {
    border-color: rgba(255, 255, 255, 0.18);
}

QComboBox:focus {
    border-color: rgba(255, 255, 255, 0.3);
}

QComboBox QAbstractItemView {
    background-color: #0b0b0d;
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 8px;
    color: #e4e4e7;
    selection-background-color: rgba(255, 255, 255, 0.08);
    selection-color: #ffffff;
}

/* Console logs styled like liquid screen */
QPlainTextEdit {
    background-color: rgba(0, 0, 0, 0.45);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 14px;
    color: #e4e4e7;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 11px;
    padding: 10px;
}

/* Glassy Progress bar */
QProgressBar {
    background-color: rgba(255, 255, 255, 0.02);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 10px;
    text-align: center;
    color: #ffffff;
    font-weight: bold;
}

QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ffffff, stop:1 #a1a1aa);
    border-radius: 8px;
}

/* Custom Scrollbar Styling */
QScrollBar:vertical {
    border: none;
    background: rgba(255, 255, 255, 0.01);
    width: 6px;
    margin: 0px;
    border-radius: 3px;
}

QScrollBar::handle:vertical {
    background: rgba(255, 255, 255, 0.10);
    min-height: 20px;
    border-radius: 3px;
}

QScrollBar::handle:vertical:hover {
    background: rgba(255, 255, 255, 0.20);
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    border: none;
    background: none;
    height: 0px;
}

QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {
    border: none;
    background: none;
    height: 0px;
}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: none;
}

QScrollBar:horizontal {
    border: none;
    background: rgba(255, 255, 255, 0.01);
    height: 6px;
    margin: 0px;
    border-radius: 3px;
}

QScrollBar::handle:horizontal {
    background: rgba(255, 255, 255, 0.10);
    min-width: 20px;
    border-radius: 3px;
}

QScrollBar::handle:horizontal:hover {
    background: rgba(255, 255, 255, 0.20);
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    border: none;
    background: none;
    width: 0px;
}

QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
    background: none;
}
"""

# -----------------------------------------------------------------------------
# Animated Toggle Switch Widget (iOS Style)
# -----------------------------------------------------------------------------
class ToggleSwitch(QAbstractButton):
    def __init__(self, parent=None, active_color="#ffffff", bg_color="rgba(255, 255, 255, 0.08)", handle_checked="#000000", handle_unchecked="#e4e4e7"):
        super().__init__(parent)
        self.setCheckable(True)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self._active_color = QColor(active_color)
        self._bg_color = QColor(bg_color)
        self._handle_checked = QColor(handle_checked)
        self._handle_unchecked = QColor(handle_unchecked)
        self._circle_position = 3.0
        self._track_color_factor = 0.0
        self.setFixedSize(54, 28)
        self.anim_pos = None
        self.anim_color = None

    @pyqtProperty(float)
    def circle_position(self):
        return self._circle_position

    @circle_position.setter
    def circle_position(self, pos):
        self._circle_position = pos
        self.update()

    @pyqtProperty(float)
    def track_color_factor(self):
        return self._track_color_factor

    @track_color_factor.setter
    def track_color_factor(self, val):
        self._track_color_factor = val
        self.update()

    def sizeHint(self):
        return QSize(54, 28)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Interpolated track color
        c1 = QColor(39, 39, 42, 200)   # #27272a, dark translucent track
        c2 = QColor(255, 255, 255, 255) # Pure white track
        
        r_val = int(c1.red() + (c2.red() - c1.red()) * self._track_color_factor)
        g_val = int(c1.green() + (c2.green() - c1.green()) * self._track_color_factor)
        b_val = int(c1.blue() + (c2.blue() - c1.blue()) * self._track_color_factor)
        a_val = int(c1.alpha() + (c2.alpha() - c1.alpha()) * self._track_color_factor)
        track_color = QColor(r_val, g_val, b_val, a_val)

        # Draw track
        p.setBrush(QBrush(track_color))
        p.setPen(QPen(QColor(255, 255, 255, 20), 1) if not self.isChecked() else Qt.PenStyle.NoPen)
        p.drawRoundedRect(QRectF(0, 0, self.width(), self.height()), self.height() / 2, self.height() / 2)

        # Draw handle drop shadow
        shadow_color = QColor(0, 0, 0, 80)
        p.setBrush(QBrush(shadow_color))
        p.setPen(Qt.PenStyle.NoPen)
        radius = (self.height() - 6) / 2
        p.drawEllipse(int(self._circle_position), 4, int(radius * 2), int(radius * 2))

        # Interpolated handle color
        hc1 = QColor(228, 228, 231) # #e4e4e7
        hc2 = QColor(0, 0, 0)       # #000000
        hr = int(hc1.red() + (hc2.red() - hc1.red()) * self._track_color_factor)
        hg = int(hc1.green() + (hc2.green() - hc1.green()) * self._track_color_factor)
        hb = int(hc1.blue() + (hc2.blue() - hc1.blue()) * self._track_color_factor)
        handle_color = QColor(hr, hg, hb)

        # Draw handle knob
        p.setBrush(QBrush(handle_color))
        p.drawEllipse(int(self._circle_position), 3, int(radius * 2), int(radius * 2))
        p.end()

    def setChecked(self, checked):
        super().setChecked(checked)
        self._circle_position = float(self.width() - self.height() + 3) if checked else 3.0
        self._track_color_factor = 1.0 if checked else 0.0
        self.update()

    def nextCheckState(self):
        self.setChecked(not self.isChecked())
        start_pos = 3.0
        end_pos = float(self.width() - self.height() + 3)
        start_color = 0.0
        end_color = 1.0
        
        if not self.isChecked():
            start_pos, end_pos = end_pos, start_pos
            start_color, end_color = end_color, start_color
            
        if self.anim_pos:
            self.anim_pos.stop()
        if self.anim_color:
            self.anim_color.stop()
            
        self.anim_pos = QPropertyAnimation(self, b"circle_position")
        self.anim_pos.setDuration(220)
        self.anim_pos.setEasingCurve(QEasingCurve.Type.OutBack)
        self.anim_pos.setStartValue(start_pos)
        self.anim_pos.setEndValue(end_pos)
        
        self.anim_color = QPropertyAnimation(self, b"track_color_factor")
        self.anim_color.setDuration(220)
        self.anim_color.setEasingCurve(QEasingCurve.Type.InOutCubic)
        self.anim_color.setStartValue(start_color)
        self.anim_color.setEndValue(end_color)
        
        self.anim_pos.start()
        self.anim_color.start()


# -----------------------------------------------------------------------------
# Animated Pulsing Status Dot Widget
# -----------------------------------------------------------------------------
class PulsingStatusDot(QWidget):
    def __init__(self, parent=None, color_name="gray"):
        super().__init__(parent)
        self.setFixedSize(24, 24)
        self._color_name = color_name
        self._glow_scale = 0.0
        
        self.anim = QPropertyAnimation(self, b"glow_scale")
        self.anim.setDuration(1500)
        self.anim.setStartValue(0.0)
        self.anim.setEndValue(1.0)
        self.anim.setLoopCount(-1) # Loop infinitely
        self.anim.start()
        
    @pyqtProperty(float)
    def glow_scale(self):
        return self._glow_scale
        
    @glow_scale.setter
    def glow_scale(self, val):
        self._glow_scale = val
        self.update()
        
    def set_status(self, color_name):
        self._color_name = color_name
        self.update()
        
    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        colors = {
            "green": QColor(166, 227, 161),
            "red": QColor(243, 139, 168),
            "yellow": QColor(249, 226, 175),
            "gray": QColor(108, 112, 134)
        }
        color = colors.get(self._color_name, colors["gray"])
        
        cx = self.width() / 2.0
        cy = self.height() / 2.0
        dot_radius = 5.0
        max_glow_radius = 11.0
        
        if self._color_name != "gray":
            glow_radius = dot_radius + (max_glow_radius - dot_radius) * self._glow_scale
            glow_opacity = 1.0 - self._glow_scale
            glow_color = QColor(color)
            glow_color.setAlphaF(glow_opacity * 0.45)
            p.setBrush(QBrush(glow_color))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(int(cx - glow_radius), int(cy - glow_radius), int(glow_radius * 2), int(glow_radius * 2))
            
        p.setBrush(QBrush(color))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(int(cx - dot_radius), int(cy - dot_radius), int(dot_radius * 2), int(dot_radius * 2))
        p.end()


# -----------------------------------------------------------------------------
# Liquid Glass Card Container Widget
# -----------------------------------------------------------------------------
class GlassCard(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self._bg_opacity = 0.02
        self._border_opacity = 0.06
        self.setMouseTracking(True)
        
        self.bg_anim = None
        self.border_anim = None

    @pyqtProperty(float)
    def bg_opacity(self):
        return self._bg_opacity

    @bg_opacity.setter
    def bg_opacity(self, val):
        self._bg_opacity = val
        self.update()

    @pyqtProperty(float)
    def border_opacity(self):
        return self._border_opacity

    @border_opacity.setter
    def border_opacity(self, val):
        self._border_opacity = val
        self.update()

    def enterEvent(self, event):
        if self.bg_anim:
            self.bg_anim.stop()
        if self.border_anim:
            self.border_anim.stop()
            
        self.bg_anim = QPropertyAnimation(self, b"bg_opacity")
        self.bg_anim.setDuration(220)
        self.bg_anim.setStartValue(self._bg_opacity)
        self.bg_anim.setEndValue(0.07)
        self.bg_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        self.border_anim = QPropertyAnimation(self, b"border_opacity")
        self.border_anim.setDuration(220)
        self.border_anim.setStartValue(self._border_opacity)
        self.border_anim.setEndValue(0.22)
        self.border_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        self.bg_anim.start()
        self.border_anim.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        if self.bg_anim:
            self.bg_anim.stop()
        if self.border_anim:
            self.border_anim.stop()
            
        self.bg_anim = QPropertyAnimation(self, b"bg_opacity")
        self.bg_anim.setDuration(250)
        self.bg_anim.setStartValue(self._bg_opacity)
        self.bg_anim.setEndValue(0.02)
        self.bg_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        self.border_anim = QPropertyAnimation(self, b"border_opacity")
        self.border_anim.setDuration(250)
        self.border_anim.setStartValue(self._border_opacity)
        self.border_anim.setEndValue(0.06)
        self.border_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        self.bg_anim.start()
        self.border_anim.start()
        super().leaveEvent(event)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        rect = self.rect()
        border_width = 1.0
        
        bg_color = QColor(255, 255, 255)
        bg_color.setAlphaF(self._bg_opacity)
        p.setBrush(QBrush(bg_color))
        
        border_color = QColor(255, 255, 255)
        border_color.setAlphaF(self._border_opacity)
        p.setPen(QPen(border_color, border_width))
        
        r = 14.0
        p.drawRoundedRect(
            QRectF(
                float(rect.x()) + border_width / 2, 
                float(rect.y()) + border_width / 2, 
                float(rect.width()) - border_width, 
                float(rect.height()) - border_width
            ), 
            r, r
        )
        p.end()


# -----------------------------------------------------------------------------
# Animated Glass Button Widget
# -----------------------------------------------------------------------------
class AnimatedButton(QPushButton):
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self._bg_opacity = 0.05
        self._border_opacity = 0.10
        self._press_opacity = 0.0
        self.setMouseTracking(True)
        
        self.bg_anim = None
        self.border_anim = None

    @pyqtProperty(float)
    def bg_opacity(self):
        return self._bg_opacity

    @bg_opacity.setter
    def bg_opacity(self, val):
        self._bg_opacity = val
        self.update()

    @pyqtProperty(float)
    def border_opacity(self):
        return self._border_opacity

    @border_opacity.setter
    def border_opacity(self, val):
        self._border_opacity = val
        self.update()

    def enterEvent(self, event):
        if self.bg_anim:
            self.bg_anim.stop()
        if self.border_anim:
            self.border_anim.stop()
            
        self.bg_anim = QPropertyAnimation(self, b"bg_opacity")
        self.bg_anim.setDuration(180)
        self.bg_anim.setStartValue(self._bg_opacity)
        self.bg_anim.setEndValue(0.12)
        self.bg_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        self.border_anim = QPropertyAnimation(self, b"border_opacity")
        self.border_anim.setDuration(180)
        self.border_anim.setStartValue(self._border_opacity)
        self.border_anim.setEndValue(0.35)
        self.border_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        self.bg_anim.start()
        self.border_anim.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        if self.bg_anim:
            self.bg_anim.stop()
        if self.border_anim:
            self.border_anim.stop()
            
        self.bg_anim = QPropertyAnimation(self, b"bg_opacity")
        self.bg_anim.setDuration(220)
        self.bg_anim.setStartValue(self._bg_opacity)
        self.bg_anim.setEndValue(0.05)
        self.bg_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        self.border_anim = QPropertyAnimation(self, b"border_opacity")
        self.border_anim.setDuration(220)
        self.border_anim.setStartValue(self._border_opacity)
        self.border_anim.setEndValue(0.10)
        self.border_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        self.bg_anim.start()
        self.border_anim.start()
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._press_opacity = 0.08
            self.update()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self._press_opacity = 0.0
        self.update()
        super().mouseReleaseEvent(event)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        rect = self.rect()
        border_width = 1.0
        r = 8.0
        
        if not self.isEnabled():
            bg_color = QColor(0, 0, 0, 50)
            p.setBrush(QBrush(bg_color))
            p.setPen(QPen(QColor(255, 255, 255, 10), border_width))
            p.drawRoundedRect(
                QRectF(
                    float(rect.x()) + border_width / 2, 
                    float(rect.y()) + border_width / 2, 
                    float(rect.width()) - border_width, 
                    float(rect.height()) - border_width
                ), 
                r, r
            )
            p.setPen(QColor(82, 82, 91))
            p.setFont(self.font())
            p.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.text())
            p.end()
            return
            
        total_bg_alpha = self._bg_opacity + self._press_opacity
        bg_color = QColor(255, 255, 255)
        bg_color.setAlphaF(total_bg_alpha)
        p.setBrush(QBrush(bg_color))
        
        border_color = QColor(255, 255, 255)
        border_color.setAlphaF(self._border_opacity)
        p.setPen(QPen(border_color, border_width))
        
        p.drawRoundedRect(
            QRectF(
                float(rect.x()) + border_width / 2, 
                float(rect.y()) + border_width / 2, 
                float(rect.width()) - border_width, 
                float(rect.height()) - border_width
            ), 
            r, r
        )
        
        if self.underMouse():
            highlight_grad = QLinearGradient(0, 0, 0, rect.height() / 2)
            highlight_grad.setColorAt(0.0, QColor(255, 255, 255, 30))
            highlight_grad.setColorAt(1.0, QColor(255, 255, 255, 0))
            p.setBrush(QBrush(highlight_grad))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRoundedRect(
                QRectF(
                    float(rect.x()) + border_width, 
                    float(rect.y()) + border_width, 
                    float(rect.width()) - border_width * 2, 
                    float(rect.height()) / 2
                ), 
                r, r
            )
            
        p.setPen(QColor(255, 255, 255))
        p.setFont(self.font())
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.text())
        p.end()

# -----------------------------------------------------------------------------
# QThread Worker for downloading files
# -----------------------------------------------------------------------------
class DownloaderThread(QThread):
    progress = pyqtSignal(int)
    status_msg = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, bin_dir):
        super().__init__()
        self.bin_dir = bin_dir
        self.urls = {
            "zapret": "https://github.com/flowseal/zapret-discord-youtube/archive/refs/heads/main.zip",
            "tg-proxy": "https://github.com/Flowseal/tg-ws-proxy/archive/refs/heads/main.zip",
            "sing-box": "https://github.com/SagerNet/sing-box/releases/download/v1.9.3/sing-box-1.9.3-windows-amd64.zip"
        }

    def run(self):
        try:
            if not os.path.exists(self.bin_dir):
                os.makedirs(self.bin_dir)

            total_items = len(self.urls)
            for idx, (name, url) in enumerate(self.urls.items()):
                self.status_msg.emit(f"Скачивание {name}...")
                temp_zip = os.path.join(self.bin_dir, f"{name}.zip")

                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req) as response:
                    total_size = int(response.info().get('Content-Length', 0))
                    downloaded = 0
                    block_size = 1024 * 64

                    with open(temp_zip, 'wb') as f:
                        while True:
                            buffer = response.read(block_size)
                            if not buffer:
                                break
                            downloaded += len(buffer)
                            f.write(buffer)
                            if total_size > 0:
                                file_progress = int((downloaded / total_size) * 100)
                                overall_progress = int((idx / total_items) * 100 + (file_progress / total_items))
                                self.progress.emit(overall_progress)
                            else:
                                self.progress.emit(int(((idx + 0.5) / total_items) * 100))

                self.status_msg.emit(f"Распаковка {name}...")
                # Extract
                with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                    zip_ref.extractall(self.bin_dir)

                # Rename the unpacked folders to canonical names
                extracted_dirs = [d for d in os.listdir(self.bin_dir) 
                                  if os.path.isdir(os.path.join(self.bin_dir, d))
                                  and d not in self.urls.keys()]

                matched_dir = None
                for d in extracted_dirs:
                    if name == 'zapret' and 'zapret' in d.lower():
                        matched_dir = d
                    elif name == 'tg-proxy' and 'tg-ws-proxy' in d.lower():
                        matched_dir = d
                    elif name == 'sing-box' and 'sing-box' in d.lower():
                        matched_dir = d

                if matched_dir:
                    src = os.path.join(self.bin_dir, matched_dir)
                    dest = os.path.join(self.bin_dir, name)
                    if os.path.exists(dest):
                        shutil.rmtree(dest)
                    os.rename(src, dest)

                try:
                    os.remove(temp_zip)
                except Exception:
                    pass

            self.progress.emit(100)
            self.finished.emit(True, "Все утилиты успешно загружены и настроены!")
        except Exception as e:
            self.finished.emit(False, f"Произошла ошибка при загрузке: {str(e)}")

# -----------------------------------------------------------------------------
# Module-level helper for server pings
# -----------------------------------------------------------------------------
def check_server_ping(srv, timeout=2.5):
    import socket
    import time
    host = srv.get("host")
    port = srv.get("port")
    if not host or not port:
        return -1
    try:
        port = int(port)
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        latency = (time.perf_counter() - start) * 1000
        return int(latency)
    except Exception:
        return -1

# -----------------------------------------------------------------------------
# Module-level helper for resource blocks checking
# -----------------------------------------------------------------------------
def check_url_access(url, timeout=5.0):
    """Check if a URL is accessible. Uses TCP fallback if HTTP fails."""
    import urllib.request
    import ssl
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,*/*',
        })
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            # Read a small chunk to confirm data flows
            data = response.read(512)
            return response.status in (200, 301, 302, 307, 308) or len(data) > 0
    except Exception:
        pass
    # Fallback: TCP connect to port 443
    try:
        import socket
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        return True
    except Exception:
        return False

def check_proxy_working(proxy_host, proxy_port, url="http://cp.cloudflare.com", timeout=5.0):
    """Check if a URL is accessible through a local HTTP/SOCKS proxy."""
    import urllib.request
    import ssl
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        proxy_url = f'http://{proxy_host}:{proxy_port}'
        proxy_handler = urllib.request.ProxyHandler({
            'http': proxy_url,
            'https': proxy_url
        })
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,*/*',
        })
        with opener.open(req, timeout=timeout) as response:
            data = response.read(512)
            return response.status in (200, 204, 301, 302, 307, 308) or len(data) > 0
    except Exception:
        return False

def is_domain(host):
    return any(c.isalpha() for c in host)

# -----------------------------------------------------------------------------
# Module-level helper for Windows Registry Proxy settings
# -----------------------------------------------------------------------------
def set_windows_proxy(enabled, server="127.0.0.1:2080"):
    import winreg
    import ctypes
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            winreg.KEY_WRITE
        )
        if enabled:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
        else:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        
        # Refresh system settings immediately
        ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)
        ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
        return True
    except Exception:
        return False

# -----------------------------------------------------------------------------
# Animated Glassmorphism Background Widget
# -----------------------------------------------------------------------------
class AnimatedBackground(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        # Orbs configurations: x, y in relative coordinates (0 to 1), r in radius, speed and color
        self.orbs = [
            {"x": 0.15, "y": 0.25, "r": 350, "dx": 0.0016, "dy": 0.0024, "color": QColor(180, 210, 255, 24)},
            {"x": 0.75, "y": 0.18, "r": 400, "dx": -0.002, "dy": 0.0012, "color": QColor(255, 255, 255, 18)},
            {"x": 0.35, "y": 0.75, "r": 380, "dx": 0.0012, "dy": -0.0018, "color": QColor(160, 160, 160, 22)},
            {"x": 0.85, "y": 0.8, "r": 320, "dx": -0.0024, "dy": -0.0014, "color": QColor(200, 220, 255, 16)}
        ]

        # Timer for ~30 FPS animation update
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_animation)
        self.timer.start(33)

    def update_animation(self):
        for orb in self.orbs:
            orb["x"] += orb["dx"]
            orb["y"] += orb["dy"]

            # Bounce from bounds
            if orb["x"] < 0 or orb["x"] > 1:
                orb["dx"] = -orb["dx"]
                orb["x"] = max(0.0, min(1.0, orb["x"]))
            if orb["y"] < 0 or orb["y"] > 1:
                orb["dy"] = -orb["dy"]
                orb["y"] = max(0.0, min(1.0, orb["y"]))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Dark base gradient
        base_grad = QLinearGradient(0, 0, 0, self.height())
        base_grad.setColorAt(0.0, QColor("#050508"))
        base_grad.setColorAt(1.0, QColor("#0f0f14"))
        painter.fillRect(self.rect(), base_grad)

        # Draw glowing radial orbs
        for orb in self.orbs:
            px = int(orb["x"] * self.width())
            py = int(orb["y"] * self.height())
            r = orb["r"]

            radial = QRadialGradient(float(px), float(py), float(r))
            radial.setColorAt(0.0, orb["color"])
            radial.setColorAt(1.0, QColor(0, 0, 0, 0))

            painter.setBrush(QBrush(radial))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(px - r, py - r, r * 2, r * 2)

        # Draw diagonal curved glass reflection highlight
        glass_grad = QLinearGradient(0, 0, self.width(), self.height())
        glass_grad.setColorAt(0.0, QColor(255, 255, 255, 12))
        glass_grad.setColorAt(0.35, QColor(255, 255, 255, 4))
        glass_grad.setColorAt(0.351, QColor(255, 255, 255, 0))
        glass_grad.setColorAt(1.0, QColor(255, 255, 255, 0))

        painter.setBrush(QBrush(glass_grad))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRect(self.rect())

        painter.end()

# -----------------------------------------------------------------------------
# Subscriptions Management Dialog
# -----------------------------------------------------------------------------
class SubscriptionsDialog(QDialog):
    def __init__(self, parent=None, subscriptions_path="", subscriptions=None, on_save_callback=None):
        super().__init__(parent)
        self.subscriptions_path = subscriptions_path
        self.subscriptions = subscriptions if subscriptions is not None else []
        self.on_save_callback = on_save_callback
        
        self.setWindowTitle("Управление подписками")
        self.setMinimumSize(550, 350)
        self.resize(600, 400)
        
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(12)
        
        title_label = QLabel("Ссылки на ваши подписки (VLESS, VMESS, SS):")
        title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #ffffff;")
        layout.addWidget(title_label)
        
        self.list_widget = QListWidget()
        self.list_widget.setStyleSheet("""
            QListWidget {
                background-color: rgba(0, 0, 0, 0.45);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 10px;
                color: #ffffff;
                padding: 5px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.03);
            }
            QListWidget::item:selected {
                background-color: rgba(255, 255, 255, 0.08);
                color: #ffffff;
                border-radius: 6px;
            }
        """)
        self.populate_list()
        layout.addWidget(self.list_widget)
        
        # Input for new subscription
        input_layout = QHBoxLayout()
        self.new_sub_input = QLineEdit()
        self.new_sub_input.setPlaceholderText("Вставьте ссылку подписки (https://...)")
        
        self.add_btn = AnimatedButton("Добавить")
        self.add_btn.clicked.connect(self.add_subscription)
        
        input_layout.addWidget(self.new_sub_input, 8)
        input_layout.addWidget(self.add_btn, 2)
        layout.addLayout(input_layout)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        self.delete_btn = AnimatedButton("Удалить выбранную")
        self.delete_btn.clicked.connect(self.delete_subscription)
        
        self.close_btn = AnimatedButton("Закрыть")
        self.close_btn.clicked.connect(self.close)
        
        btn_layout.addWidget(self.delete_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.close_btn)
        layout.addLayout(btn_layout)
        
    def populate_list(self):
        self.list_widget.clear()
        for sub in self.subscriptions:
            self.list_widget.addItem(sub)
            
    def add_subscription(self):
        url = self.new_sub_input.text().strip()
        if not url:
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            self.new_sub_input.setStyleSheet("border: 1px solid #ef4444;")
            QTimer.singleShot(2000, lambda: self.new_sub_input.setStyleSheet(""))
            return
            
        if url not in self.subscriptions:
            self.subscriptions.append(url)
            self.populate_list()
            self.new_sub_input.clear()
            if self.on_save_callback:
                self.on_save_callback()
                
    def delete_subscription(self):
        selected_items = self.list_widget.selectedItems()
        if not selected_items:
            return
        for item in selected_items:
            url = item.text()
            if url in self.subscriptions:
                self.subscriptions.remove(url)
        self.populate_list()
        if self.on_save_callback:
            self.on_save_callback()

# -----------------------------------------------------------------------------
# Main Application Window
# -----------------------------------------------------------------------------
class MainWindow(QMainWindow):
    log_signal = pyqtSignal(str)
    import_done_signal = pyqtSignal(bool)  # True = success, triggers UI update from main thread
    ping_done_signal = pyqtSignal()
    block_status_signal = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Bypass & VPN Manager")
        self.setMinimumSize(800, 700)
        self.resize(850, 780)
        self.setStyleSheet(CATPPUCCIN_STYLE)

        # Window Icon
        icon_path = os.path.join(get_project_dir(), "app_icon.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # Paths
        self.project_dir = get_project_dir()
        self.bin_dir = os.path.join(self.project_dir, "bin")
        
        # Fallback to parent directory if local 'bin' doesn't exist (e.g. running from 'dist' folder)
        if not os.path.exists(self.bin_dir):
            parent_bin = os.path.join(os.path.dirname(self.project_dir), "bin")
            if os.path.exists(parent_bin):
                self.bin_dir = parent_bin
                
        # Resolve config path with fallback
        self.config_path = os.path.join(self.project_dir, "vpn_keys.json")
        if not os.path.exists(self.config_path):
            parent_config = os.path.join(os.path.dirname(self.project_dir), "vpn_keys.json")
            if os.path.exists(parent_config):
                self.config_path = parent_config

        self.subscriptions_path = os.path.join(self.project_dir, "subscriptions.json")
        self.subscriptions = []

        # Process control pointers
        self.processes = {
            "zapret": None,
            "tg-proxy": None,
            "vpn": None
        }
        self.vpn_servers = []
        self._tg_proxy_link = None

        # Setup Signals
        self.log_signal.connect(self.append_log)
        self.import_done_signal.connect(self._on_import_done)
        self.ping_done_signal.connect(self.on_ping_done)
        self.block_status_signal.connect(self.on_block_status_checked)

        # Build UI Elements
        self.init_ui()

        # Check First Run / Dependency check
        self.check_dependencies()

    def init_ui(self):
        # Main Layout
        central_widget = AnimatedBackground(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(12)

        # Header Title Area
        header_layout = QHBoxLayout()
        title_text_layout = QVBoxLayout()
        
        title_label = QLabel("P U L M A N   B Y P A S S")
        title_label.setObjectName("main-title")
        title_text_layout.addWidget(title_label)
        
        subtitle_label = QLabel("Управление модулями обхода блокировок и VPN (Требуются права Администратора)")
        subtitle_label.setObjectName("main-subtitle")
        title_text_layout.addWidget(subtitle_label)

        header_layout.addLayout(title_text_layout)
        header_layout.addStretch()
        
        # Admin Indicator Badge
        admin_badge = QLabel("ADMIN ACCESS" if is_admin() else "NO ADMIN")
        admin_badge.setStyleSheet(
            "border: 1px solid rgba(255, 255, 255, 0.25); background-color: rgba(255, 255, 255, 0.08); color: #ffffff; font-weight: bold; border-radius: 6px; padding: 6px 12px;"
            if is_admin() else
            "border: 1px solid rgba(244, 63, 94, 0.35); background-color: rgba(244, 63, 94, 0.08); color: #f43f5e; font-weight: bold; border-radius: 6px; padding: 6px 12px;"
        )
        header_layout.addWidget(admin_badge)
        main_layout.addLayout(header_layout)

        # Layout for cards directly inside main_layout to eliminate scrollbars
        main_layout.setSpacing(10)

        # ---------------------------------------------------------------------
        # Card 0: Block Status Checker
        # ---------------------------------------------------------------------
        status_card = GlassCard()
        status_layout = QHBoxLayout(status_card)
        status_layout.setContentsMargins(15, 12, 15, 12)

        status_info_layout = QVBoxLayout()
        status_title = QLabel("Проверка разблокировки сайтов")
        status_title.setObjectName("card-title")
        status_info_layout.addWidget(status_title)

        # Status Grid
        status_grid = QGridLayout()
        status_grid.setSpacing(10)
        
        # YouTube status layout
        yt_layout = QHBoxLayout()
        yt_layout.setSpacing(6)
        self.yt_dot = PulsingStatusDot(color_name="gray")
        self.youtube_status_label = QLabel("Не проверено")
        self.youtube_status_label.setStyleSheet("color: #a1a1aa; font-weight: bold;")
        yt_layout.addWidget(self.yt_dot)
        yt_layout.addWidget(self.youtube_status_label)
        yt_layout.addStretch()
        
        # ChatGPT status layout
        cg_layout = QHBoxLayout()
        cg_layout.setSpacing(6)
        self.cg_dot = PulsingStatusDot(color_name="gray")
        self.chatgpt_status_label = QLabel("Не проверено")
        self.chatgpt_status_label.setStyleSheet("color: #a1a1aa; font-weight: bold;")
        cg_layout.addWidget(self.cg_dot)
        cg_layout.addWidget(self.chatgpt_status_label)
        cg_layout.addStretch()
        
        # Discord status layout
        dc_layout = QHBoxLayout()
        dc_layout.setSpacing(6)
        self.dc_dot = PulsingStatusDot(color_name="gray")
        self.discord_status_label = QLabel("Не проверено")
        self.discord_status_label.setStyleSheet("color: #a1a1aa; font-weight: bold;")
        dc_layout.addWidget(self.dc_dot)
        dc_layout.addWidget(self.discord_status_label)
        dc_layout.addStretch()
        
        # SoundCloud status layout
        sc_layout = QHBoxLayout()
        sc_layout.setSpacing(6)
        self.sc_dot = PulsingStatusDot(color_name="gray")
        self.soundcloud_status_label = QLabel("Не проверено")
        self.soundcloud_status_label.setStyleSheet("color: #a1a1aa; font-weight: bold;")
        sc_layout.addWidget(self.sc_dot)
        sc_layout.addWidget(self.soundcloud_status_label)
        sc_layout.addStretch()
        
        youtube_lbl = QLabel("YouTube:")
        youtube_lbl.setStyleSheet("color: #e4e4e7; font-weight: bold;")
        chatgpt_lbl = QLabel("ChatGPT:")
        chatgpt_lbl.setStyleSheet("color: #e4e4e7; font-weight: bold;")
        discord_lbl = QLabel("Discord:")
        discord_lbl.setStyleSheet("color: #e4e4e7; font-weight: bold;")
        soundcloud_lbl = QLabel("SoundCloud:")
        soundcloud_lbl.setStyleSheet("color: #e4e4e7; font-weight: bold;")
        
        status_grid.addWidget(youtube_lbl, 0, 0)
        status_grid.addLayout(yt_layout, 0, 1)
        status_grid.addWidget(chatgpt_lbl, 0, 2)
        status_grid.addLayout(cg_layout, 0, 3)
        
        status_grid.addWidget(discord_lbl, 1, 0)
        status_grid.addLayout(dc_layout, 1, 1)
        status_grid.addWidget(soundcloud_lbl, 1, 2)
        status_grid.addLayout(sc_layout, 1, 3)
        
        status_info_layout.addLayout(status_grid)
        status_layout.addLayout(status_info_layout, 7)
        status_layout.addStretch(1)

        self.check_status_btn = AnimatedButton("Проверить доступность")
        self.check_status_btn.clicked.connect(self.check_blocks_status)
        status_layout.addWidget(self.check_status_btn)

        status_container = QWidget()
        status_container_layout = QVBoxLayout(status_container)
        status_container_layout.setContentsMargins(0, 0, 0, 0)
        status_container_layout.addWidget(status_card)
        main_layout.addWidget(status_container)

        # ---------------------------------------------------------------------
        # Card 1: Zapret Manager
        # ---------------------------------------------------------------------
        zapret_card = GlassCard()
        zapret_layout = QHBoxLayout(zapret_card)
        zapret_layout.setContentsMargins(15, 12, 15, 12)

        zapret_info_layout = QVBoxLayout()
        zapret_title = QLabel("Zapret (YouTube & Discord Bypass)")
        zapret_title.setObjectName("card-title")
        zapret_desc = QLabel("Обход DPI блокировок на основе WinDivert драйвера.")
        zapret_desc.setObjectName("card-description")
        zapret_info_layout.addWidget(zapret_title)
        zapret_info_layout.addWidget(zapret_desc)

        preset_layout = QHBoxLayout()
        preset_label = QLabel("Пресет:")
        self.preset_combo = QComboBox()
        self.preset_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        preset_layout.addWidget(preset_label)
        preset_layout.addWidget(self.preset_combo)
        zapret_info_layout.addLayout(preset_layout)

        zapret_layout.addLayout(zapret_info_layout, 7)
        zapret_layout.addStretch(1)

        self.zapret_switch = ToggleSwitch()
        self.zapret_switch.clicked.connect(self.toggle_zapret)
        zapret_layout.addWidget(self.zapret_switch)

        zapret_container = QWidget()
        zapret_container_layout = QVBoxLayout(zapret_container)
        zapret_container_layout.setContentsMargins(0, 0, 0, 0)
        zapret_container_layout.addWidget(zapret_card)
        main_layout.addWidget(zapret_container)

        # ---------------------------------------------------------------------
        # Card 2: TG WS Proxy Manager
        # ---------------------------------------------------------------------
        tg_card = GlassCard()
        tg_layout = QHBoxLayout(tg_card)
        tg_layout.setContentsMargins(15, 12, 15, 12)

        tg_info_layout = QVBoxLayout()
        tg_title = QLabel("Telegram WS Proxy")
        tg_title.setObjectName("card-title")
        tg_desc = QLabel("Локальный прокси-сервер MTProto для обхода ограничений загрузки в Telegram.")
        tg_desc.setObjectName("card-description")
        tg_info_layout.addWidget(tg_title)
        tg_info_layout.addWidget(tg_desc)

        tg_link_row = QHBoxLayout()
        self.tg_link_label = QLabel("Ссылка для Telegram: не запущено")
        self.tg_link_label.setObjectName("card-description")
        self.tg_link_label.setStyleSheet("color: #89b4fa; font-weight: bold;")
        self.tg_link_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        tg_link_row.addWidget(self.tg_link_label, 1)

        self.tg_copy_btn = AnimatedButton("Копировать ссылку")
        self.tg_copy_btn.setFixedWidth(130)
        self.tg_copy_btn.clicked.connect(self.copy_tg_link)
        self.tg_copy_btn.setVisible(False)
        tg_link_row.addWidget(self.tg_copy_btn)
        tg_info_layout.addLayout(tg_link_row)

        tg_layout.addLayout(tg_info_layout, 7)
        tg_layout.addStretch(1)

        self.tg_switch = ToggleSwitch()
        self.tg_switch.clicked.connect(self.toggle_tg_proxy)
        tg_layout.addWidget(self.tg_switch)

        tg_container = QWidget()
        tg_container_layout = QVBoxLayout(tg_container)
        tg_container_layout.setContentsMargins(0, 0, 0, 0)
        tg_container_layout.addWidget(tg_card)
        main_layout.addWidget(tg_container)

        # ---------------------------------------------------------------------
        # Card 3: VPN Manager (Sing-Box)
        # ---------------------------------------------------------------------
        vpn_card = GlassCard()
        vpn_layout = QVBoxLayout(vpn_card)
        vpn_layout.setContentsMargins(15, 12, 15, 12)
        vpn_layout.setSpacing(10)

        vpn_header_layout = QHBoxLayout()
        vpn_info_layout = QVBoxLayout()
        vpn_title = QLabel("VPN Client (Sing-box)")
        vpn_title.setObjectName("card-title")
        vpn_desc = QLabel("Полноценный клиент VPN с поддержкой Shadowsocks, VLESS и VMESS ключей.")
        vpn_desc.setObjectName("card-description")
        vpn_info_layout.addWidget(vpn_title)
        vpn_info_layout.addWidget(vpn_desc)
        vpn_header_layout.addLayout(vpn_info_layout, 7)
        vpn_header_layout.addStretch(1)

        self.vpn_switch = ToggleSwitch()
        self.vpn_switch.clicked.connect(self.toggle_vpn)
        vpn_header_layout.addWidget(self.vpn_switch)
        vpn_layout.addLayout(vpn_header_layout)

        # Key Input & Import button
        input_layout = QHBoxLayout()
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Вставьте ключ (ss://, vless://, vmess://) или ссылку подписки...")
        
        self.import_btn = AnimatedButton("Импорт")
        self.import_btn.clicked.connect(self.import_vpn_key)
        
        self.file_import_btn = AnimatedButton("Файл...")
        self.file_import_btn.setToolTip("Импортировать ключи из .txt/.json файла")
        self.file_import_btn.clicked.connect(self.import_keys_from_file)
        
        input_layout.addWidget(self.key_input, 7)
        input_layout.addWidget(self.import_btn, 2)
        input_layout.addWidget(self.file_import_btn, 2)
        vpn_layout.addLayout(input_layout)

        # Server selection list
        server_layout = QHBoxLayout()
        server_label = QLabel("Сервер:")
        self.server_combo = QComboBox()
        self.server_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        server_layout.addWidget(server_label, 2)
        server_layout.addWidget(self.server_combo, 8)
        vpn_layout.addLayout(server_layout)

        # Status row
        self.vpn_status_label = QLabel("")
        self.vpn_status_label.setStyleSheet("color: #a1a1aa; font-size: 11px;")
        vpn_layout.addWidget(self.vpn_status_label)

        # Row of actions
        actions_layout = QHBoxLayout()
        
        self.refresh_btn = AnimatedButton("Обновить список")
        self.refresh_btn.clicked.connect(self.refresh_vless_list_async)
        
        self.sub_mgr_btn = AnimatedButton("Подписки...")
        self.sub_mgr_btn.clicked.connect(self.open_subscriptions_manager)
        
        self.ping_btn = AnimatedButton("Пропинговать")
        self.ping_btn.clicked.connect(self.ping_all_servers)
        
        self.remove_offline_btn = AnimatedButton("Удалить нерабочие")
        self.remove_offline_btn.clicked.connect(self.remove_offline_servers)
        
        actions_layout.addWidget(self.refresh_btn)
        actions_layout.addWidget(self.sub_mgr_btn)
        actions_layout.addWidget(self.ping_btn)
        actions_layout.addWidget(self.remove_offline_btn)
        vpn_layout.addLayout(actions_layout)

        vpn_container = QWidget()
        vpn_container_layout = QVBoxLayout(vpn_container)
        vpn_container_layout.setContentsMargins(0, 0, 0, 0)
        vpn_container_layout.addWidget(vpn_card)
        main_layout.addWidget(vpn_container)

        # ---------------------------------------------------------------------
        # Downloader Progress overlay area (for first setup)
        # ---------------------------------------------------------------------
        self.downloader_frame = GlassCard()
        self.downloader_frame.setStyleSheet("background-color: rgba(0, 0, 0, 0.45); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 12px;")
        downloader_layout = QVBoxLayout(self.downloader_frame)
        downloader_layout.setContentsMargins(15, 12, 15, 12)
        
        self.download_status = QLabel("Первый запуск: Требуется скачать утилиты (Zapret, TG WS Proxy, Sing-box)...")
        self.download_status.setStyleSheet("font-weight: bold; color: #ffffff;")
        downloader_layout.addWidget(self.download_status)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        downloader_layout.addWidget(self.progress_bar)

        self.start_download_btn = AnimatedButton("Начать автоматическую загрузку")
        self.start_download_btn.clicked.connect(self.start_downloads)
        downloader_layout.addWidget(self.start_download_btn)

        downloader_container = QWidget()
        downloader_container_layout = QVBoxLayout(downloader_container)
        downloader_container_layout.setContentsMargins(0, 0, 0, 0)
        downloader_container_layout.addWidget(self.downloader_frame)
        main_layout.addWidget(downloader_container)
        downloader_container.setVisible(False)

        # ---------------------------------------------------------------------
        # Log Console Console (Bottom part)
        # ---------------------------------------------------------------------
        log_label = QLabel("Консоль логов событий")
        log_label.setStyleSheet("font-weight: bold; color: #a6adc8; font-size: 11px; margin-top: 5px;")

        self.log_console = QPlainTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setMaximumHeight(120)
        self.log_console.setMinimumHeight(80)

        console_container = QWidget()
        console_container_layout = QVBoxLayout(console_container)
        console_container_layout.setContentsMargins(0, 0, 0, 0)
        console_container_layout.addWidget(log_label)
        console_container_layout.addWidget(self.log_console)
        main_layout.addWidget(console_container)

        # Set up entry animations target list
        self.animated_widgets = [
            status_container,
            zapret_container,
            tg_container,
            vpn_container,
            console_container
        ]

        # Apply premium liquid-glass shadows directly to GlassCard / QPlainTextEdit
        self.apply_premium_shadow(status_card)
        self.apply_premium_shadow(zapret_card)
        self.apply_premium_shadow(tg_card)
        self.apply_premium_shadow(vpn_card)
        self.apply_premium_shadow(self.downloader_frame)
        self.apply_premium_shadow(self.log_console)

        self.append_log("[Инфо] Приложение запущено с правами Администратора.")

        # Trigger startup animations
        QTimer.singleShot(100, self.start_entry_animations)

    def apply_premium_shadow(self, widget):
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(22)
        shadow.setColor(QColor(0, 0, 0, 160))
        shadow.setOffset(0, 6)
        widget.setGraphicsEffect(shadow)

    def start_entry_animations(self):
        self._effects = []
        self._anims = []
        
        for idx, widget in enumerate(self.animated_widgets):
            effect = QGraphicsOpacityEffect(widget)
            effect.setOpacity(0.0)
            widget.setGraphicsEffect(effect)
            self._effects.append(effect)
            
            anim = QPropertyAnimation(effect, b"opacity")
            anim.setDuration(450)
            anim.setStartValue(0.0)
            anim.setEndValue(1.0)
            anim.setEasingCurve(QEasingCurve.Type.OutCubic)
            
            # Clean up the graphics effect on completion to restore standard paint logic and prevent nested shadow layout bugs
            anim.finished.connect(lambda w=widget: w.setGraphicsEffect(None))
            
            delay = idx * 120
            QTimer.singleShot(delay, anim.start)
            self._anims.append(anim)

    # -----------------------------------------------------------------------------
    # Logging helper
    # -----------------------------------------------------------------------------
    def append_log(self, text):
        timestamp = time.strftime("[%H:%M:%S]")
        self.log_console.appendPlainText(f"{timestamp} {text}")
        self.log_console.verticalScrollBar().setValue(self.log_console.verticalScrollBar().maximum())

    def copy_tg_link(self):
        if self._tg_proxy_link:
            clipboard = QApplication.clipboard()
            clipboard.setText(self._tg_proxy_link)
            self.append_log("[Инфо] Ссылка на прокси скопирована в буфер обмена.")

    # -----------------------------------------------------------------------------
    # Check Dependencies / Fill GUI values
    # -----------------------------------------------------------------------------
    def check_dependencies(self):
        zapret_ok = os.path.exists(os.path.join(self.bin_dir, "zapret"))
        tg_ok = os.path.exists(os.path.join(self.bin_dir, "tg-proxy"))
        singbox_ok = os.path.exists(os.path.join(self.bin_dir, "sing-box", "sing-box.exe"))

        if not (zapret_ok and tg_ok and singbox_ok):
            self.downloader_frame.setVisible(True)
            self.disable_controls(True)
            self.append_log("[Внимание] Не все необходимые утилиты обнаружены. Требуется загрузка.")
        else:
            self.downloader_frame.setVisible(False)
            self.disable_controls(False)
            self.load_presets()
            self.load_saved_vpn_keys()
            self.load_subscriptions()
            
            # Clean up lingering processes on startup
            try:
                self.cleanup_singbox()
                self.cleanup_tg_proxy()
                self.cleanup_windivert()
                set_windows_proxy(False)
            except Exception as e:
                self.append_log(f"[Очистка] Ошибка при очистке процессов: {str(e)}")
            
            # Start hourly auto-updater QTimer
            self.auto_update_timer = QTimer(self)
            self.auto_update_timer.timeout.connect(self.refresh_vless_list_async)
            self.auto_update_timer.start(60 * 60 * 1000) # Every 1 hour
            
            # Trigger initial refresh on startup in the background
            QTimer.singleShot(1000, self.refresh_vless_list_async)

    def disable_controls(self, disable):
        self.zapret_switch.setEnabled(not disable)
        self.preset_combo.setEnabled(not disable)
        self.tg_switch.setEnabled(not disable)
        self.vpn_switch.setEnabled(not disable)
        self.key_input.setEnabled(not disable)
        self.import_btn.setEnabled(not disable)
        self.server_combo.setEnabled(not disable)
        self.refresh_btn.setEnabled(not disable)
        if hasattr(self, 'sub_mgr_btn'):
            self.sub_mgr_btn.setEnabled(not disable)
        self.ping_btn.setEnabled(not disable)
        self.remove_offline_btn.setEnabled(not disable)
        self.check_status_btn.setEnabled(not disable)
        self.file_import_btn.setEnabled(not disable)

    def open_subscriptions_manager(self):
        dialog = SubscriptionsDialog(self, self.subscriptions_path, self.subscriptions, self.save_subscriptions)
        dialog.exec()

    def load_presets(self):
        # Scan bin/zapret/ directory for bat files
        zapret_path = os.path.join(self.bin_dir, "zapret")
        if not os.path.exists(zapret_path):
            return

        self.preset_combo.clear()
        bat_files = [f for f in os.listdir(zapret_path) if f.endswith('.bat')]
        
        # Place common general presets first
        bat_files.sort(key=lambda x: 0 if 'general' in x.lower() or 'discord_only' in x.lower() else 1)
        
        if bat_files:
            self.preset_combo.addItems(bat_files)
            self.append_log(f"[Инфо] Обнаружено {len(bat_files)} батников-пресетов Zapret.")
        else:
            self.append_log("[Ошибка] В папке bin/zapret не обнаружено .bat файлов.")

    def load_saved_vpn_keys(self):
        # Load keys from self.config_path
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.vpn_servers = json.load(f)
                self.update_server_combo()
                self.append_log(f"[Инфо] Загружено {len(self.vpn_servers)} сохраненных серверов VPN.")
            except Exception as e:
                self.append_log(f"[Ошибка] Не удалось загрузить vpn_keys.json: {str(e)}")

    def save_vpn_keys(self):
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.vpn_servers, f, indent=4, ensure_ascii=False)
        except Exception as e:
            self.append_log(f"[Ошибка] Не удалось сохранить vpn_keys.json: {str(e)}")

    def load_subscriptions(self):
        self.subscriptions = []
        if os.path.exists(self.subscriptions_path):
            try:
                with open(self.subscriptions_path, "r", encoding="utf-8") as f:
                    self.subscriptions = json.load(f)
                self.append_log(f"[Инфо] Загружено {len(self.subscriptions)} подписок.")
            except Exception as e:
                self.append_log(f"[Ошибка] Не удалось загрузить subscriptions.json: {str(e)}")
        else:
            self.save_subscriptions()

    def save_subscriptions(self):
        try:
            with open(self.subscriptions_path, "w", encoding="utf-8") as f:
                json.dump(self.subscriptions, f, indent=4, ensure_ascii=False)
        except Exception as e:
            self.append_log(f"[Ошибка] Не удалось сохранить subscriptions.json: {str(e)}")

    def update_server_combo(self):
        self.server_combo.clear()
        for idx, srv in enumerate(self.vpn_servers):
            ping_val = srv.get('ping', None)
            if ping_val is None:
                ping_str = "—"
            elif ping_val == -1:
                ping_str = "Offline"
            else:
                ping_str = f"{ping_val} ms"
            
            # Display name: Ping + Tag + (IP/Host)
            display = f"[{ping_str}] {srv['tag']} ({srv['host']}:{srv['port']}) [{srv['type'].upper()}]"
            self.server_combo.addItem(display, idx)

    def _on_import_done(self, success):
        """Called on main thread when background import finishes."""
        self.import_btn.setEnabled(True)
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("Обновить список")
        self.vpn_status_label.setText("Список серверов обновлен.")
        if success:
            self.update_server_combo()
            self.server_combo.setCurrentIndex(self.server_combo.count() - 1)

    # -----------------------------------------------------------------------------
    # Async Download trigger
    # -----------------------------------------------------------------------------
    def start_downloads(self):
        self.start_download_btn.setEnabled(False)
        self.download_status.setText("Загрузка началась. Пожалуйста, подождите...")
        
        self.downloader_thread = DownloaderThread(self.bin_dir)
        self.downloader_thread.progress.connect(self.progress_bar.setValue)
        self.downloader_thread.status_msg.connect(self.append_log)
        self.downloader_thread.finished.connect(self.on_download_finished)
        self.downloader_thread.start()

    def on_download_finished(self, success, message):
        if success:
            self.append_log(f"[Успех] {message}")
            self.downloader_frame.setVisible(False)
            self.disable_controls(False)
            self.load_presets()
        else:
            self.append_log(f"[Ошибка] {message}")
            self.download_status.setText("Ошибка загрузки! См. логи.")
            self.start_download_btn.setEnabled(True)

    # -----------------------------------------------------------------------------
    # Process tree execution & reading output
    # -----------------------------------------------------------------------------
    def run_process_reader(self, process, prefix):
        def reader():
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                # Filter out binary/trash characters if any
                clean_line = line.strip()
                if clean_line:
                    self.log_signal.emit(f"[{prefix}] {clean_line}")
        threading.Thread(target=reader, daemon=True).start()

    def stop_process_group(self, key):
        proc = self.processes[key]
        if not proc:
            return

        self.append_log(f"[Инфо] Остановка модуля {key}...")
        try:
            # psutil tree kill
            parent = psutil.Process(proc.pid)
            for child in parent.children(recursive=True):
                try:
                    child.kill()
                except Exception:
                    pass
            parent.kill()
        except Exception:
            # Fallback to taskkill if psutil fails or process not found
            subprocess.run(f"taskkill /F /T /PID {proc.pid}", shell=True, creationflags=subprocess.CREATE_NO_WINDOW)

        self.processes[key] = None
        self.append_log(f"[Инфо] Модуль {key} успешно остановлен.")

    # -----------------------------------------------------------------------------
    # Module 1: Zapret (Discord & YouTube bypass) Control
    # -----------------------------------------------------------------------------
    def toggle_zapret(self, checked):
        if checked:
            preset = self.preset_combo.currentText()
            if not preset:
                self.append_log("[Ошибка] Не выбран пресет для запуска Zapret.")
                self.zapret_switch.setChecked(False)
                return

            zapret_dir = os.path.join(self.bin_dir, "zapret")
            preset_path = os.path.join(zapret_dir, preset)

            self.append_log(f"[Запуск] Запуск Zapret с пресетом: {preset}...")
            
            # Zapret batch file sets directories. We run it within its directory.
            try:
                # Use subprocess to run the batch script without a console window
                proc = subprocess.Popen(
                    [preset_path],
                    cwd=zapret_dir,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                self.processes["zapret"] = proc
                self.run_process_reader(proc, "Zapret")
                self.append_log("[Успех] Модуль Zapret запущен.")
            except Exception as e:
                self.append_log(f"[Ошибка] Ошибка при запуске пресета Zapret: {str(e)}")
                self.zapret_switch.setChecked(False)
        else:
            self.stop_process_group("zapret")
            # Explicit cleanup of winws.exe processes and windivert service
            self.cleanup_windivert()

    def cleanup_windivert(self):
        # Scan and terminate any orphaned winws.exe processes
        terminated_count = 0
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'].lower() == 'winws.exe':
                    proc.kill()
                    terminated_count += 1
            except Exception:
                pass
        
        if terminated_count > 0:
            self.append_log(f"[Очистка] Завершено {terminated_count} процессов winws.exe.")

        # Command SC to stop and delete the driver service
        subprocess.run("sc stop WinDivert", shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run("sc delete WinDivert", shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        self.append_log("[Очистка] Служба WinDivert выгружена.")

    def cleanup_singbox(self):
        terminated_count = 0
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'].lower() in ('sing-box.exe', 'sing-box'):
                    proc.kill()
                    terminated_count += 1
            except Exception:
                pass
        if terminated_count > 0:
            self.append_log(f"[Очистка] Завершено {terminated_count} процессов sing-box.exe.")

    def cleanup_tg_proxy(self):
        terminated_count = 0
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                name = proc.info.get('name') or ""
                cmd = proc.info.get('cmdline') or []
                if any('tg_ws_proxy.py' in arg for arg in cmd) or 'tgwsproxy_windows.exe' in name.lower():
                    proc.kill()
                    terminated_count += 1
            except Exception:
                pass
        if terminated_count > 0:
            self.append_log(f"[Очистка] Завершено {terminated_count} процессов Telegram WS Proxy.")

    # -----------------------------------------------------------------------------
    # Module 2: Telegram WS Proxy Control
    # -----------------------------------------------------------------------------
    def toggle_tg_proxy(self, checked):
        if checked:
            tg_dir = os.path.join(self.bin_dir, "tg-proxy")
            tg_exe = os.path.join(tg_dir, "TgWsProxy_windows.exe")
            tg_ws_proxy_py = os.path.join(tg_dir, "proxy", "tg_ws_proxy.py")

            # Load or generate config from %APPDATA%\TgWsProxy\config.json
            tg_appdata = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'TgWsProxy')
            if not os.path.exists(tg_appdata):
                os.makedirs(tg_appdata)
            tg_config_path = os.path.join(tg_appdata, "config.json")
            
            secret = ""
            port = 1443
            host = "127.0.0.1"
            
            tg_cfg = {}
            if os.path.exists(tg_config_path):
                try:
                    with open(tg_config_path, "r", encoding="utf-8") as f:
                        tg_cfg = json.load(f)
                    secret = tg_cfg.get("secret", "")
                    port = tg_cfg.get("port", 1443)
                    host = tg_cfg.get("host", "127.0.0.1")
                except Exception:
                    pass
            
            if not secret or len(secret) != 32:
                secret = os.urandom(16).hex()
                tg_cfg["secret"] = secret
                tg_cfg["port"] = port
                tg_cfg["host"] = host
                tg_cfg.setdefault("dc_ip", ["2:149.154.167.220", "4:149.154.167.220"])
                tg_cfg.setdefault("verbose", False)
                tg_cfg.setdefault("check_updates", True)
                tg_cfg.setdefault("log_max_mb", 5)
                tg_cfg.setdefault("buf_kb", 256)
                tg_cfg.setdefault("pool_size", 4)
                tg_cfg.setdefault("cfproxy", True)
                tg_cfg.setdefault("cfproxy_user_domain", [])
                tg_cfg.setdefault("cfproxy_worker_domain", [])
                try:
                    with open(tg_config_path, "w", encoding="utf-8") as f:
                        json.dump(tg_cfg, f, indent=2, ensure_ascii=False)
                except Exception:
                    pass

            self.append_log(f"[Запуск] Запуск Telegram WS Proxy...")
            
            if os.path.exists(tg_exe):
                # Run the precompiled exe directly (no python dependency, perfect for other users)
                try:
                    proc = subprocess.Popen(
                        [tg_exe],
                        cwd=tg_dir,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                    )
                    self.processes["tg-proxy"] = proc
                    self.append_log("[Успех] Telegram WS Proxy запущен в трее из TgWsProxy_windows.exe.")
                except Exception as e:
                    self.append_log(f"[Ошибка] Не удалось запустить TgWsProxy_windows.exe: {str(e)}")
                    self.tg_switch.setChecked(False)
                    return
            else:
                # Fallback to python script if executable is missing
                if not os.path.exists(tg_ws_proxy_py):
                    self.append_log("[Ошибка] Утилита Telegram WS Proxy не найдена.")
                    self.tg_switch.setChecked(False)
                    return

                python_exe = sys.executable
                if getattr(sys, 'frozen', False):
                    py_path = shutil.which("py")
                    if py_path:
                        python_exe = py_path
                    else:
                        python_path = shutil.which("python")
                        if python_path and "WindowsApps" not in python_path:
                            python_exe = python_path
                        else:
                            python_exe = "py"

                try:
                    proc = subprocess.Popen(
                        [
                            python_exe, tg_ws_proxy_py,
                            "--host", host,
                            "--port", str(port),
                            "--secret", secret,
                            "-v"
                        ],
                        cwd=tg_dir,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1
                    )
                    self.processes["tg-proxy"] = proc
                    self.run_process_reader(proc, "TG-Proxy")
                    self.append_log("[Успех] Telegram WS Proxy запущен из python-скрипта.")
                except Exception as e:
                    self.append_log(f"[Ошибка] Не удалось запустить tg_ws_proxy.py: {str(e)}")
                    self.tg_switch.setChecked(False)
                    return

            # Format and show link in GUI, and trigger auto-open
            tg_link = f"tg://proxy?server={host}&port={port}&secret=dd{secret}"
            self._tg_proxy_link = tg_link
            self.tg_link_label.setText(f"Ссылка: {tg_link}")
            self.tg_copy_btn.setVisible(True)
            self.append_log(f"[Инфо]   Тип: MTProto | Сервер: {host} | Порт: {port} | Секрет: dd{secret}")

            def open_tg_link():
                try:
                    os.startfile(tg_link)
                    self.append_log("[Инфо] Ссылка отправлена в Telegram — подтвердите подключение к прокси в приложении.")
                except Exception as ex:
                    self.append_log(f"[Ошибка] Не удалось открыть Telegram: {str(ex)}")

            QTimer.singleShot(1500, open_tg_link)
        else:
            self.stop_process_group("tg-proxy")
            self.cleanup_tg_proxy()
            self.tg_link_label.setText("Ссылка для Telegram: не запущено")
            self.tg_copy_btn.setVisible(False)
            self._tg_proxy_link = None

    # -----------------------------------------------------------------------------
    # Module 3: VPN (Sing-Box) Control & Import Logic
    # -----------------------------------------------------------------------------
    def import_vpn_key(self):
        text = self.key_input.text().strip()
        if not text:
            self.append_log("[Ошибка] Поле ввода ключа пусто.")
            return

        # Check if URL subscription link
        if text.startswith("http://") or text.startswith("https://"):
            self.append_log(f"[Импорт] Запрос подписки по ссылке: {text}...")
            self.import_btn.setEnabled(False)
            
            # Save to subscriptions list
            if text not in self.subscriptions:
                self.subscriptions.append(text)
                self.save_subscriptions()
                self.append_log(f"[Импорт] Ссылка добавлена в список подписок.")
            
            def run_import():
                try:
                    servers = fetch_subscription(text)
                    if servers:
                        for s in servers:
                            s['is_custom'] = False
                        self.vpn_servers.extend(servers)
                        # Remove duplicates based on host, port, type, tag
                        seen = set()
                        unique_servers = []
                        for s in self.vpn_servers:
                            key = (s['host'], s['port'], s['type'], s['tag'])
                            if key not in seen:
                                seen.add(key)
                                unique_servers.append(s)
                        self.vpn_servers = unique_servers
                        self.save_vpn_keys()
                        self.log_signal.emit(f"[Импорт] Успешно импортировано {len(servers)} серверов из подписки.")
                        self.import_done_signal.emit(True)
                    else:
                        self.log_signal.emit("[Импорт] Серверы не найдены в подписке.")
                        self.import_done_signal.emit(False)
                except Exception as e:
                    self.log_signal.emit(f"[Импорт] Ошибка загрузки подписки: {str(e)}")
                    self.import_done_signal.emit(False)

            threading.Thread(target=run_import, daemon=True).start()
            self.key_input.clear()
            return

        # Check if Xray/v2ray JSON config
        if text.strip().startswith('{'):
            self._import_xray_json(text)
            self.key_input.clear()
            return

        # Regular single key import
        try:
            srv = parse_vpn_key(text)
            if srv:
                srv['is_custom'] = True
                self.vpn_servers.append(srv)
                self.save_vpn_keys()
                self.update_server_combo()
                self.server_combo.setCurrentIndex(self.server_combo.count() - 1)
                self.append_log(f"[Импорт] Успешно импортирован сервер: {srv['tag']}")
                self.key_input.clear()
        except Exception as e:
            self.append_log(f"[Ошибка] Ошибка импорта ключа: {str(e)}")

    def _import_xray_json(self, text):
        """Import server from Xray/v2ray JSON config."""
        try:
            cfg = json.loads(text)
            outbounds = cfg.get('outbounds', [])
            name = cfg.get('remarks', 'Imported Server')
            imported = 0
            for ob in outbounds:
                proto = ob.get('protocol', '')
                if proto not in ('vless', 'vmess', 'shadowsocks'):
                    continue
                settings = ob.get('settings', {})
                stream = ob.get('streamSettings', {})
                network = stream.get('network', 'tcp')
                security = stream.get('security', 'none')

                if proto == 'vless':
                    for vnext in settings.get('vnext', []):
                        for user in vnext.get('users', []):
                            reality = stream.get('realitySettings', {})
                            tls = stream.get('tlsSettings', {})
                            srv = {
                                'type': 'vless',
                                'host': vnext.get('address', ''),
                                'port': int(vnext.get('port', 443)),
                                'uuid': user.get('id', ''),
                                'security': security,
                                'network': network,
                                'sni': reality.get('serverName', '') or tls.get('serverName', ''),
                                'fp': reality.get('fingerprint', '') or tls.get('fingerprint', ''),
                                'pbk': reality.get('publicKey', ''),
                                'sid': reality.get('shortId', ''),
                                'flow': user.get('flow', ''),
                                'path': (stream.get('grpcSettings', {}).get('serviceName', '') or
                                         stream.get('wsSettings', {}).get('path', '') or ''),
                                'tag': name,
                                'is_custom': True
                            }
                            self.vpn_servers.append(srv)
                            imported += 1

                elif proto == 'vmess':
                    for vnext in settings.get('vnext', []):
                        for user in vnext.get('users', []):
                            tls_s = stream.get('tlsSettings', {})
                            srv = {
                                'type': 'vmess',
                                'host': vnext.get('address', ''),
                                'port': int(vnext.get('port', 443)),
                                'uuid': user.get('id', ''),
                                'aid': int(user.get('alterId', 0)),
                                'net': network,
                                'type_header': 'none',
                                'path': (stream.get('wsSettings', {}).get('path', '') or ''),
                                'sni': tls_s.get('serverName', ''),
                                'tls': security if security == 'tls' else '',
                                'tag': name,
                                'is_custom': True
                            }
                            self.vpn_servers.append(srv)
                            imported += 1

            if imported > 0:
                self.save_vpn_keys()
                self.update_server_combo()
                self.server_combo.setCurrentIndex(self.server_combo.count() - 1)
                self.append_log(f"[Импорт] Успешно импортировано {imported} сервер(ов) из Xray JSON конфига.")
            else:
                self.append_log("[Импорт] В JSON конфиге не найдено поддерживаемых серверов.")
        except json.JSONDecodeError as e:
            self.append_log(f"[Ошибка] Неверный JSON формат: {str(e)}")
        except Exception as e:
            self.append_log(f"[Ошибка] Ошибка импорта JSON конфига: {str(e)}")

    def refresh_vless_list_async(self):
        """Fetch VLESS/VMESS/SS servers from the remote subscription URLs in a background thread."""
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("Обновление...")
        self.vpn_status_label.setText("Загрузка списка серверов...")
        self.append_log("[Импорт] Запуск фонового обновления списка серверов...")

        def worker():
            urls = self.subscriptions
            if not urls:
                self.log_signal.emit("[Импорт] Список подписок пуст. Вы можете добавить ссылки на подписки в меню «Подписки...»")
                self.import_done_signal.emit(False)
                return

            new_servers = []
            
            for url in urls:
                self.log_signal.emit(f"[Импорт] Загрузка серверов из подписки: {url}...")
                try:
                    servers = fetch_subscription(url)
                    if servers:
                        for s in servers:
                            s['is_custom'] = False
                        new_servers.extend(servers)
                        self.log_signal.emit(f"[Импорт] Получено {len(servers)} серверов из подписки: {url}")
                    else:
                        self.log_signal.emit(f"[Импорт] Серверы не найдены в подписке {url}.")
                except Exception as e:
                    self.log_signal.emit(f"[Ошибка] Не удалось загрузить подписку {url}: {str(e)}")

            if new_servers:
                # Keep custom/manually imported ones (default is True if not set)
                custom_servers = [s for s in self.vpn_servers if s.get('is_custom', True)]
                
                # Deduplicate new servers based on host, port, type, and tag
                seen = set()
                unique_new = []
                for s in new_servers:
                    key = (s['host'], s['port'], s['type'], s['tag'])
                    if key not in seen:
                        seen.add(key)
                        unique_new.append(s)
                        
                self.vpn_servers = custom_servers + unique_new
                self.save_vpn_keys()
                self.log_signal.emit(f"[Импорт] Обновление завершено. Всего серверов: {len(self.vpn_servers)} ({len(custom_servers)} пользовательских, {len(unique_new)} из подписок).")
                self.import_done_signal.emit(True)
            else:
                self.log_signal.emit("[Импорт] Не удалось найти новые серверы в подписках.")
                self.import_done_signal.emit(False)

        threading.Thread(target=worker, daemon=True).start()

    def ping_all_servers(self):
        """Pings all servers in parallel and updates their latency values."""
        if not self.vpn_servers:
            self.append_log("[Пинг] Нет серверов для пинга.")
            return

        self.ping_btn.setEnabled(False)
        self.ping_btn.setText("Проверка...")
        self.vpn_status_label.setText("Проверка задержки серверов...")
        self.append_log("[Пинг] Запуск проверки задержки серверов...")

        def worker():
            from concurrent.futures import ThreadPoolExecutor
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(check_server_ping, srv): srv for srv in self.vpn_servers}
                for future in futures:
                    srv = futures[future]
                    try:
                        latency = future.result()
                        srv['ping'] = latency
                    except Exception:
                        srv['ping'] = -1
            
            self.ping_done_signal.emit()

        threading.Thread(target=worker, daemon=True).start()

    def on_ping_done(self):
        self.ping_btn.setEnabled(True)
        self.ping_btn.setText("Пропинговать")
        self.vpn_status_label.setText("Проверка задержки завершена.")
        self.update_server_combo()
        self.save_vpn_keys()
        self.append_log("[Пинг] Проверка всех серверов завершена.")

    def remove_offline_servers(self):
        """Removes all offline (ping == -1) servers from the list."""
        original_count = len(self.vpn_servers)
        
        # Keep servers that are online (ping >= 0) or haven't been pinged yet (None)
        self.vpn_servers = [s for s in self.vpn_servers if s.get('ping', 0) >= 0 or s.get('ping') is None]
        removed = original_count - len(self.vpn_servers)
        
        self.save_vpn_keys()
        self.update_server_combo()
        self.append_log(f"[Очистка] Удалено {removed} нерабочих серверов. Осталось: {len(self.vpn_servers)}")

    def check_blocks_status(self):
        """Checks accessibility of YouTube, ChatGPT, Discord, and SoundCloud."""
        self.check_status_btn.setEnabled(False)
        self.check_status_btn.setText("Тестирование...")
        
        self.youtube_status_label.setText("Проверка...")
        self.chatgpt_status_label.setText("Проверка...")
        self.discord_status_label.setText("Проверка...")
        self.soundcloud_status_label.setText("Проверка...")
        
        self.yt_dot.set_status("yellow")
        self.cg_dot.set_status("yellow")
        self.dc_dot.set_status("yellow")
        self.sc_dot.set_status("yellow")
        
        is_vpn_active = self.processes["vpn"] is not None

        def worker():
            port_to_use = 2080
            results = {}
            
            try:
                targets = {
                    "youtube": "https://www.youtube.com",
                    "chatgpt": "https://chatgpt.com",
                    "discord": "https://discord.com",
                    "soundcloud": "https://soundcloud.com"
                }
                
                from concurrent.futures import ThreadPoolExecutor
                
                def test_one(item):
                    name, url = item
                    if is_vpn_active:
                        ok = check_proxy_working("127.0.0.1", port_to_use, url, timeout=6.0)
                    else:
                        ok = check_url_access(url, timeout=6.0)
                    return name, ok
                    
                with ThreadPoolExecutor(max_workers=4) as executor:
                    futures = [executor.submit(test_one, item) for item in targets.items()]
                    for f in futures:
                        name, ok = f.result()
                        results[name] = ok
            except Exception as e:
                self.log_signal.emit(f"[Ошибка] Сбой во время проверки сайтов: {str(e)}")
            finally:
                self.block_status_signal.emit(results)
            
        threading.Thread(target=worker, daemon=True).start()

    def on_block_status_checked(self, results):
        self.check_status_btn.setEnabled(True)
        self.check_status_btn.setText("Проверить доступность")
        
        # YouTube
        if results.get("youtube"):
            self.youtube_status_label.setText("Доступен")
            self.youtube_status_label.setStyleSheet("color: #a6e3a1; font-weight: bold;")
            self.yt_dot.set_status("green")
        else:
            self.youtube_status_label.setText("Заблокирован")
            self.youtube_status_label.setStyleSheet("color: #f38ba8; font-weight: bold;")
            self.yt_dot.set_status("red")
            
        # ChatGPT
        if results.get("chatgpt"):
            self.chatgpt_status_label.setText("Доступен")
            self.chatgpt_status_label.setStyleSheet("color: #a6e3a1; font-weight: bold;")
            self.cg_dot.set_status("green")
        else:
            self.chatgpt_status_label.setText("Заблокирован")
            self.chatgpt_status_label.setStyleSheet("color: #f38ba8; font-weight: bold;")
            self.cg_dot.set_status("red")

        # Discord
        if results.get("discord"):
            self.discord_status_label.setText("Доступен")
            self.discord_status_label.setStyleSheet("color: #a6e3a1; font-weight: bold;")
            self.dc_dot.set_status("green")
        else:
            self.discord_status_label.setText("Заблокирован")
            self.discord_status_label.setStyleSheet("color: #f38ba8; font-weight: bold;")
            self.dc_dot.set_status("red")

        # SoundCloud
        if results.get("soundcloud"):
            self.soundcloud_status_label.setText("Доступен")
            self.soundcloud_status_label.setStyleSheet("color: #a6e3a1; font-weight: bold;")
            self.sc_dot.set_status("green")
        else:
            self.soundcloud_status_label.setText("Заблокирован")
            self.soundcloud_status_label.setStyleSheet("color: #f38ba8; font-weight: bold;")
            self.sc_dot.set_status("red")
            
        is_vpn_active = self.processes["vpn"] is not None
        source = "VPN" if is_vpn_active else "Тест-Сервер"
        self.append_log(f"[Статус] Тест доступности ({source}): YouTube={'OK' if results.get('youtube') else 'FAIL'} | ChatGPT={'OK' if results.get('chatgpt') else 'FAIL'} | Discord={'OK' if results.get('discord') else 'FAIL'} | SoundCloud={'OK' if results.get('soundcloud') else 'FAIL'}")

    def import_keys_from_file(self):
        """Allows importing VLESS/VMESS/Shadowsocks keys or Xray JSON configs from a local file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выбрать файл с ключами",
            "",
            "Текстовые файлы (*.txt);;JSON конфигурации (*.json);;Все файлы (*)"
        )
        if not file_path:
            return
            
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                
            # If JSON config format
            if file_path.endswith('.json') or content.strip().startswith('{'):
                self._import_xray_json(content)
                return
                
            # If plain text file containing links line by line
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            added = 0
            for line in lines:
                if line.startswith('vless://') or line.startswith('vmess://') or line.startswith('ss://'):
                    try:
                        srv = parse_vpn_key(line)
                        if srv:
                            srv['is_custom'] = True
                            self.vpn_servers.append(srv)
                            added += 1
                    except Exception:
                        continue
            if added:
                self.save_vpn_keys()
                self.update_server_combo()
                self.append_log(f"[Импорт] Импортировано {added} серверов из файла {os.path.basename(file_path)}.")
            else:
                self.append_log("[Импорт] В файле не найдено поддерживаемых ключей.")
        except Exception as e:
            self.append_log(f"[Ошибка] Ошибка при чтении файла: {str(e)}")

    def test_vpn_connectivity(self):
        """Performs a real HTTP tunnel check through the local proxy to verify if VPN is working."""
        if not self.processes["vpn"]:
            return
            
        self.vpn_status_label.setText("Тестирование соединения...")
        
        def worker():
            working = check_proxy_working("127.0.0.1", 2080)
            if working:
                self.log_signal.emit("[VPN] Тест соединения: УСПЕШНО! Интернет через VPN работает.")
                QTimer.singleShot(0, lambda: self.vpn_status_label.setText("🟢 Подключено (Интернет доступен)"))
            else:
                self.log_signal.emit("[VPN] Тест соединения: СБОЙ! Трафик не проходит (сервер оффлайн или ключ недействителен).")
                QTimer.singleShot(0, self._on_vpn_test_failed)
                
        threading.Thread(target=worker, daemon=True).start()

    def _on_vpn_test_failed(self):
        self.vpn_status_label.setText("🔴 Сбой подключения (Проверьте сервер)")
        self.vpn_switch.setChecked(False)
        self.toggle_vpn(False)

    def toggle_vpn(self, checked):
        if checked:
            try:
                self.cleanup_singbox()
            except Exception as e:
                self.append_log(f"[Очистка] Ошибка при очистке sing-box: {str(e)}")
            idx = self.server_combo.currentIndex()
            if idx < 0 or idx >= len(self.vpn_servers):
                self.append_log("[Ошибка] Не выбран сервер для подключения.")
                self.vpn_switch.setChecked(False)
                return

            srv = self.vpn_servers[idx]
            self.append_log(f"[Подключение] Инициализация подключения к {srv['tag']} ({srv['host']}) ...")

            # Generate configuration JSON for sing-box
            try:
                config_json = self.generate_singbox_config(srv)
                config_path = os.path.join(self.bin_dir, "sing-box", "config.json")
                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump(config_json, f, indent=4)
                
                self.append_log("[Конфиг] Временный config.json для sing-box успешно сохранен.")
            except Exception as e:
                self.append_log(f"[Ошибка] Не удалось сгенерировать конфиг sing-box: {str(e)}")
                self.vpn_switch.setChecked(False)
                return

            # Start process
            singbox_exe = os.path.join(self.bin_dir, "sing-box", "sing-box.exe")
            try:
                proc = subprocess.Popen(
                    [singbox_exe, "run", "-c", "config.json"],
                    cwd=os.path.join(self.bin_dir, "sing-box"),
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                self.processes["vpn"] = proc
                self.run_process_reader(proc, "VPN")
                
                # Apply system proxy settings in registry
                if set_windows_proxy(True, "127.0.0.1:2080"):
                    self.append_log("[Успех] Системный прокси Windows перенаправлен на 127.0.0.1:2080.")
                else:
                    self.append_log("[Внимание] Не удалось настроить системный прокси в реестре Windows.")
                
                # Block QUIC UDP 443 to force fallback to TCP (which goes through system proxy)
                try:
                    subprocess.run('netsh advfirewall firewall delete rule name="Block-QUIC-UDP-443"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    subprocess.run('netsh advfirewall firewall add rule name="Block-QUIC-UDP-443" dir=out action=block protocol=UDP localport=any remoteport=443', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    self.append_log("[Инфо] Заблокирован трафик QUIC (UDP 443) для перенаправления YouTube в TCP-туннель.")
                except Exception as ex:
                    self.append_log(f"[Внимание] Не удалось настроить брандмауэр для QUIC: {str(ex)}")
                
                self.append_log("[Успех] Служба VPN успешно запущена.")
                
                # Schedule real proxy connectivity test in 2.5 seconds
                QTimer.singleShot(2500, self.test_vpn_connectivity)
            except Exception as e:
                self.append_log(f"[Ошибка] Не удалось запустить sing-box: {str(e)}")
                self.vpn_switch.setChecked(False)
        else:
            self.stop_process_group("vpn")
            set_windows_proxy(False)
            self.append_log("[Очистка] Системный прокси Windows отключен.")
            
            # Remove firewall rule
            try:
                subprocess.run('netsh advfirewall firewall delete rule name="Block-QUIC-UDP-443"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                self.append_log("[Очистка] Правило блокировки QUIC удалено из брандмауэра.")
            except Exception:
                pass

    def generate_singbox_config(self, srv):
        proxy_host = srv.get("host", "")
        outbound = {
            "type": srv["type"],
            "tag": "proxy-out",
            "server": srv["host"],
            "server_port": srv["port"]
        }

        if srv["type"] == "shadowsocks":
            outbound["method"] = srv["method"]
            outbound["password"] = srv["password"]

        elif srv["type"] == "vless":
            outbound["uuid"] = srv["uuid"]
            if srv["flow"]:
                outbound["flow"] = srv["flow"]
            
            # Security TLS / Reality
            if srv["security"] in ("tls", "reality"):
                tls_config = {
                    "enabled": True,
                    "server_name": srv["sni"] if srv["sni"] else srv["host"]
                }
                if srv["security"] == "reality":
                    tls_config["reality"] = {
                        "enabled": True,
                        "public_key": srv["pbk"],
                        "short_id": srv["sid"] if srv["sid"] else ""
                    }
                if srv["fp"]:
                    tls_config["utls"] = {
                        "enabled": True,
                        "fingerprint": srv["fp"]
                    }
                outbound["tls"] = tls_config

            # Transport
            net = srv.get("network", "tcp")
            if net == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": srv["path"] if srv.get("path") else "/"
                }
            elif net == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": srv.get("path", "") or ""
                }
            elif net == "h2":
                outbound["transport"] = {
                    "type": "http",
                    "path": srv.get("path", "/") or "/"
                }

        elif srv["type"] == "vmess":
            outbound["uuid"] = srv["uuid"]
            outbound["alter_id"] = srv["aid"]
            outbound["security"] = "auto"

            # TLS config
            if srv["tls"] == "tls":
                tls_config = {
                    "enabled": True,
                    "server_name": srv["sni"] if srv["sni"] else srv["host"]
                }
                outbound["tls"] = tls_config

            # Transport
            net = srv.get("net", "tcp")
            if net == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": srv.get("path", "/") or "/"
                }
            elif net == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": srv.get("path", "") or ""
                }

        # Build full JSON
        dns_rules = []
        if proxy_host and is_domain(proxy_host):
            dns_rules.append({
                "domain": [proxy_host],
                "server": "dns-local"
            })

        config_structure = {
            "log": {
                "level": "info"
            },
            "dns": {
                "servers": [
                    {
                        "tag": "dns-remote",
                        "address": "https://8.8.8.8/dns-query",
                        "detour": "proxy-out"
                    },
                    {
                        "tag": "dns-local",
                        "address": "local",
                        "detour": "direct-out"
                    }
                ],
                "rules": dns_rules
            },
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": 2080,
                    "set_system_proxy": False
                }
            ],
            "outbounds": [
                outbound,
                {
                    "type": "direct",
                    "tag": "direct-out"
                },
                {
                    "type": "dns",
                    "tag": "dns-out"
                }
            ],
            "route": {
                "rules": [
                    {
                        "protocol": "dns",
                        "outbound": "dns-out"
                    }
                ]
            }
        }
        return config_structure

    # -----------------------------------------------------------------------------
    # Close Handler to terminate subprocesses
    # -----------------------------------------------------------------------------
    def closeEvent(self, event):
        self.append_log("[Выход] Завершение всех запущенных модулей перед закрытием...")
        
        # Stop everything
        if self.processes["zapret"]:
            self.stop_process_group("zapret")
            self.cleanup_windivert()
        if self.processes["tg-proxy"]:
            self.stop_process_group("tg-proxy")
        if self.processes["vpn"]:
            self.stop_process_group("vpn")
        
        # Always disable system proxy on exit to prevent deadlock
        try:
            set_windows_proxy(False)
        except Exception:
            pass
            
        # Always clean up firewall rule on exit
        try:
            subprocess.run('netsh advfirewall firewall delete rule name="Block-QUIC-UDP-443"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

        event.accept()

# -----------------------------------------------------------------------------
# App Entry Point
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        # Check and prompt UAC elevation before starting app
        run_as_admin()

        # Extract bundled resources to %APPDATA%/pulman-bypass on first run
        extract_bundled_resources()

        app = QApplication(sys.argv)
        
        # Set default fonts
        font = QFont("Segoe UI", 9)
        app.setFont(font)

        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        log_crash(e)
        raise
