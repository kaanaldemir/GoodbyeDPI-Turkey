from __future__ import annotations

import ctypes
import http.client
import os
import queue
import shutil
import ssl
import subprocess
import sys
import threading
import time
import tkinter as tk
from typing import Callable
from tkinter import messagebox
from tkinter import ttk

APP_NAME = "Discord Erişim Aracı"
RESOURCE_DIR_NAME = "goodbyedpi-0.2.3rc3-turkey"

BG_COLOR = "#f4f6fb"
CARD_COLOR = "#ffffff"
ACCENT_COLOR = "#1f5ed6"
ACCENT_DARK = "#1a4fb3"
TEXT_COLOR = "#0f172a"
MUTED_COLOR = "#475569"
BORDER_COLOR = "#d6dee8"
STATUS_OK_BG = "#dcfce7"
STATUS_OK_FG = "#166534"
STATUS_WARN_BG = "#fef9c3"
STATUS_WARN_FG = "#854d0e"
STATUS_ERR_BG = "#fee2e2"
STATUS_ERR_FG = "#991b1b"
STATUS_INFO_BG = "#e2e8f0"
STATUS_INFO_FG = "#334155"
BUSY_BG = "#fff4cc"
BUSY_FG = "#92400e"
UNINSTALL_BG = "#e2e8f0"
UNINSTALL_FG = TEXT_COLOR
UNINSTALL_ACTIVE_BG = "#cbd5f5"
CANCEL_BG = "#fecaca"
CANCEL_FG = "#7f1d1d"
CANCEL_ACTIVE_BG = "#fca5a5"

INSTALL_SUCCESS = "success"
INSTALL_FAILED = "failed"
INSTALL_CANCELLED = "cancelled"


def get_oem_encoding() -> str:
    try:
        codepage = ctypes.windll.kernel32.GetOEMCP()
        return f"cp{codepage}"
    except Exception:
        return "mbcs"


OEM_ENCODING = get_oem_encoding()

DNS_PROVIDERS = [
    {
        "id": "yandex",
        "label": "Yandex (Standart)",
        "v4": "77.88.8.8",
        "v6": "2a02:6b8::feed:0ff",
        "port": 1253,
    },
    {
        "id": "cloudflare",
        "label": "Cloudflare (Standart)",
        "v4": "1.1.1.1",
        "v6": "2606:4700:4700::1111",
        "port": 53,
    },
    {
        "id": "google",
        "label": "Google (Standart)",
        "v4": "8.8.8.8",
        "v6": "2001:4860:4860::8888",
        "port": 53,
    },
    {
        "id": "quad9",
        "label": "Quad9 (Güvenli)",
        "v4": "9.9.9.9",
        "v6": "2620:fe::fe",
        "port": 53,
    },
    {
        "id": "opendns",
        "label": "OpenDNS (Standart)",
        "v4": "208.67.222.222",
        "v6": "2620:119:35::35",
        "port": 53,
    },
    {
        "id": "adguard",
        "label": "AdGuard (Filtreli)",
        "v4": "94.140.14.14",
        "v6": "2a10:50c0::ad1:ff",
        "port": 53,
    },
    {
        "id": "adguard_nofilter",
        "label": "AdGuard (Filtre Yok)",
        "v4": "94.140.14.140",
        "v6": "2a10:50c0::1:ff",
        "port": 53,
    },
    {
        "id": "adguard_family",
        "label": "AdGuard (Aile)",
        "v4": "94.140.14.15",
        "v6": "2a10:50c0::bad1:ff",
        "port": 53,
    },
    {
        "id": "cloudflare_malware",
        "label": "Cloudflare (Zararlı Engelli)",
        "v4": "1.1.1.2",
        "v6": "2606:4700:4700::1112",
        "port": 53,
    },
    {
        "id": "cloudflare_family",
        "label": "Cloudflare (Zararlı + Yetişkin)",
        "v4": "1.1.1.3",
        "v6": "2606:4700:4700::1113",
        "port": 53,
    },
]

AUTO_PROVIDER_IDS = ["yandex", "cloudflare", "google", "quad9", "opendns", "adguard"]
PROVIDER_BY_ID = {provider["id"]: provider for provider in DNS_PROVIDERS}

VARIANTS = [
    (
        "Varsayılan",
        "-5 --set-ttl 5 --dns-addr {v4} --dns-port {port} --dnsv6-addr {v6} --dnsv6-port {port}",
    ),
    ("Alternatif 1", "--set-ttl 3 --dns-addr {v4} --dns-port {port} --dnsv6-addr {v6}"),
    (
        "Alternatif 2",
        "-5 --dns-addr {v4} --dns-port {port} --dnsv6-addr {v6} --dnsv6-port {port}",
    ),
]

TEST_TARGETS = [
    ("discord.com", "/api/v9/gateway"),
    ("discord.com", "/"),
]
TEST_TIMEOUT = 6
STATUS_TEST_TIMEOUT = 3
STATUS_REFRESH_MS = 5000

LOCALAPPDATA = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or os.path.expanduser("~")
APPDATA_BASE = os.path.join(LOCALAPPDATA, "DiscordErisim")
LOG_PATH = os.path.join(APPDATA_BASE, "discord_erisimi.log")
PROGRAMFILES = os.environ.get("ProgramFiles", r"C:\\Program Files")
TARGET_BASE = os.path.join(PROGRAMFILES, "Discord")
TARGET_DIR = os.path.join(TARGET_BASE, RESOURCE_DIR_NAME)

log_queue: "queue.Queue[str]" = queue.Queue()
log_lock = threading.Lock()


def log(message: str) -> None:
    timestamp = time.strftime("%H:%M:%S")
    line = f"[{timestamp}] {message}"
    log_queue.put(line)
    try:
        os.makedirs(APPDATA_BASE, exist_ok=True)
        with log_lock:
            with open(LOG_PATH, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
    except Exception:
        pass


def resource_root() -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS  # type: ignore[attr-defined]
    return os.path.dirname(os.path.abspath(__file__))


def arch_dir() -> str:
    arch = os.environ.get("PROCESSOR_ARCHITECTURE", "")
    arch_w6432 = os.environ.get("PROCESSOR_ARCHITEW6432", "")
    if arch_w6432 or arch.upper().endswith("64"):
        return "x86_64"
    return "x86"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def quote(arg: str) -> str:
    return f'"{arg}"'


def relaunch_as_admin() -> bool:
    args = [arg for arg in sys.argv[1:] if arg != "--elevated"]
    args.append("--elevated")

    if getattr(sys, "frozen", False):
        params = " ".join(quote(arg) for arg in args)
        exe = sys.executable
    else:
        script = os.path.abspath(sys.argv[0])
        params = " ".join([quote(script)] + [quote(arg) for arg in args])
        exe = sys.executable

    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    return rc > 32


def run_cmd(command: str) -> bool:
    log(f"> {command}")
    proc = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        encoding=OEM_ENCODING,
        errors="replace",
    )
    if proc.stdout:
        log(proc.stdout.strip())
    if proc.stderr:
        log(proc.stderr.strip())
    return proc.returncode == 0


def query_service(name: str) -> tuple[str, str]:
    proc = subprocess.run(
        f'sc query "{name}"',
        shell=True,
        capture_output=True,
        text=True,
        encoding=OEM_ENCODING,
        errors="replace",
    )
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if "1060" in output or "does not exist" in output.lower():
        return "missing", output
    if "RUNNING" in output:
        return "running", output
    if "STOPPED" in output:
        return "stopped", output
    if "STATE" in output:
        return "exists", output
    return "unknown", output


def get_service_status() -> tuple[str, str]:
    state, _ = query_service("GoodbyeDPI")
    if state == "running":
        return "running", "Kurulu • Çalışıyor"
    if state == "stopped":
        return "stopped", "Kurulu • Durdurulmuş"
    if state == "missing":
        return "missing", "Kurulu değil"
    return "unknown", "Durum bilinmiyor"


def remove_service(name: str, log_missing: bool = False) -> None:
    state, _ = query_service(name)
    if state == "missing":
        if log_missing:
            log(f"{name} hizmeti bulunamadı, atlandı.")
        return
    run_cmd(f'sc stop "{name}"')
    run_cmd(f'sc delete "{name}"')


def remove_services(log_missing: bool = False) -> None:
    for service in ["GoodbyeDPI", "WinDivert", "WinDivert14"]:
        remove_service(service, log_missing=log_missing)


def copy_resources() -> None:
    source_dir = os.path.join(resource_root(), RESOURCE_DIR_NAME)
    if not os.path.isdir(source_dir):
        raise FileNotFoundError(
            f"{RESOURCE_DIR_NAME} bulunamadı. Bu klasör uygulamanın yanında olmalı."
        )

    os.makedirs(TARGET_BASE, exist_ok=True)
    shutil.copytree(source_dir, TARGET_DIR, dirs_exist_ok=True)


def install_service(exe_path: str, args: str) -> bool:
    bin_path = f'\\"{exe_path}\\" {args}'
    remove_service("GoodbyeDPI", log_missing=False)
    created = run_cmd(f'sc create "GoodbyeDPI" binPath= "{bin_path}" start= "auto"')
    if not created:
        return False
    run_cmd('sc description "GoodbyeDPI" "Türkiye için DNS zorlamasını kaldırır."')
    return run_cmd('sc start "GoodbyeDPI"')


def test_discord(
    timeout: int = 6,
    status_cb: Callable[[str], None] | None = None,
    step_text: str = "",
    cancel_event: threading.Event | None = None,
) -> tuple[bool, str]:
    def set_stage(message: str) -> None:
        if status_cb is not None:
            status_cb(message)

    def _try_target(host: str, path: str) -> tuple[bool, str]:
        url_label = f"https://{host}{path}"
        try:
            context = ssl.create_default_context()
            if hasattr(ssl, "OP_NO_TICKET"):
                context.options |= ssl.OP_NO_TICKET
            if hasattr(ssl, "TLSVersion"):
                context.minimum_version = ssl.TLSVersion.TLSv1_2

            conn = http.client.HTTPSConnection(host, timeout=timeout, context=context)
            conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0", "Connection": "close"})
            response = conn.getresponse()
            response.read()
            conn.close()
            return True, f"{url_label} -> HTTP {response.status}"
        except Exception as exc:
            return False, f"{url_label} -> {exc}"

    last_error = ""
    for host, path in TEST_TARGETS:
        result_queue: "queue.Queue[tuple[bool, str]]" = queue.Queue(maxsize=1)

        def worker() -> None:
            result_queue.put(_try_target(host, path))

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        remaining = timeout
        while True:
            if cancel_event is not None and cancel_event.is_set():
                return False, "İptal edildi"
            set_stage(f"Discord bağlantısı test ediliyor {step_text} — Kalan: {remaining} sn")
            try:
                ok, detail = result_queue.get(timeout=1)
                if ok:
                    return True, detail
                last_error = detail
                break
            except queue.Empty:
                remaining -= 1
                if remaining <= 0:
                    last_error = f"https://{host}{path} -> süre aşımı"
                    break
    return False, last_error or "Bağlantı testi başarısız."


def provider_list(choice: str) -> list[dict[str, object]]:
    if choice == "auto":
        return [PROVIDER_BY_ID[provider_id] for provider_id in AUTO_PROVIDER_IDS]
    provider = PROVIDER_BY_ID.get(choice)
    if provider:
        return [provider]
    return [PROVIDER_BY_ID[provider_id] for provider_id in AUTO_PROVIDER_IDS]


def install_auto(
    choice: str,
    status_cb: Callable[[str], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> str:
    def set_stage(message: str) -> None:
        if status_cb is not None:
            status_cb(message)

    def is_cancelled() -> bool:
        return cancel_event is not None and cancel_event.is_set()

    def handle_cancel() -> bool:
        if not is_cancelled():
            return False
        set_stage("İptal ediliyor. Hizmetler kaldırılıyor.")
        log("İptal istendi. Hizmetler kaldırılıyor.")
        uninstall_only(status_cb=status_cb)
        return True

    providers = provider_list(choice)
    total_steps = max(1, len(providers) * len(VARIANTS))
    step_index = 0

    set_stage(f"Hazırlık (0/{total_steps}) — Dosyalar hazırlanıyor.")
    log("Dosyalar hazırlanıyor...")
    copy_resources()
    if handle_cancel():
        return INSTALL_CANCELLED
    set_stage(f"Hazırlık (0/{total_steps}) — Önceki hizmetler kaldırılıyor.")
    log("Hizmetler kaldırılıyor...")
    remove_services(log_missing=False)
    if handle_cancel():
        return INSTALL_CANCELLED

    exe_path = os.path.join(TARGET_DIR, arch_dir(), "goodbyedpi.exe")
    if not os.path.isfile(exe_path):
        log(f"Uygulama dosyası bulunamadı: {exe_path}")
        return INSTALL_FAILED

    for provider in providers:
        provider_label = str(provider["label"])
        for variant_label, template in VARIANTS:
            if handle_cancel():
                return INSTALL_CANCELLED
            step_index += 1
            step_text = f"({step_index}/{total_steps})"
            set_stage(f"Deneme {step_text}: {provider_label} - {variant_label}")
            log(f"Deneniyor: {provider_label} - {variant_label}")
            args = template.format(v4=provider["v4"], v6=provider["v6"], port=provider["port"])
            if not install_service(exe_path, args):
                log("Kurulum başarısız, sonraki seçenek deneniyor.")
                continue
            time.sleep(2)
            set_stage(f"Discord bağlantısı test ediliyor {step_text} — Kalan: {TEST_TIMEOUT} sn")
            ok, detail = test_discord(
                timeout=TEST_TIMEOUT,
                status_cb=status_cb,
                step_text=step_text,
                cancel_event=cancel_event,
            )
            if handle_cancel():
                return INSTALL_CANCELLED
            log(f"Test sonucu: {detail}")
            if ok:
                set_stage(f"Başarılı {step_text}. Kurulum tamamlandı.")
                log("Discord bağlantısı başarılı görünüyor.")
                return INSTALL_SUCCESS
            log("Test başarısız, sonraki seçenek deneniyor.")

    log("Tüm yöntemler denendi. Farklı bir DNS seçip tekrar deneyin.")
    if handle_cancel():
        return INSTALL_CANCELLED

    cleanup_step = total_steps + 1
    cleanup_text = f"({cleanup_step}/{cleanup_step})"
    set_stage(f"Kaldırma {cleanup_text}: Başarısız kurulum temizleniyor.")
    uninstall_only(status_cb=status_cb)
    return INSTALL_FAILED


def uninstall_only(status_cb: Callable[[str], None] | None = None) -> bool:
    if status_cb is not None:
        status_cb("Hizmetler kaldırılıyor.")
    log("Hizmetler kaldırılıyor...")
    remove_services(log_missing=True)
    log("Kaldırma tamamlandı. Dosyalar silinmedi.")
    return True


class DiscordErisimApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("760x520")
        self.minsize(720, 480)
        self.configure(bg=BG_COLOR)
        self.option_add("*Font", ("Segoe UI", 10))

        self.choice_var = tk.StringVar(value="Otomatik (Önerilen)")
        self.busy = False
        self.status_label: tk.Label | None = None
        self.busy_label: tk.Label | None = None
        self._current_stage = ""
        self._cancel_event = threading.Event()
        self._current_task: str | None = None
        self._status_check_inflight = False
        self._last_access_state: str | None = None

        self._build_ui()
        self.after(100, self._process_logs)
        self.after(200, self._schedule_status_refresh)

    def _build_ui(self) -> None:
        header = tk.Frame(self, bg=ACCENT_COLOR, padx=18, pady=16)
        header.pack(fill=tk.X)

        title = tk.Label(
            header,
            text=APP_NAME,
            bg=ACCENT_COLOR,
            fg="white",
            font=("Bahnschrift", 18, "bold"),
        )
        title.pack(anchor=tk.W)

        subtitle = tk.Label(
            header,
            text="Discord erişimi için tek tıkla kurulum ve otomatik test.",
            bg=ACCENT_COLOR,
            fg="#dbe7ff",
            font=("Segoe UI", 10),
        )
        subtitle.pack(anchor=tk.W, pady=(4, 0))

        body = tk.Frame(self, bg=BG_COLOR, padx=18, pady=16)
        body.pack(fill=tk.BOTH, expand=True)

        info = tk.Label(
            body,
            text="Bu araç gerekli hizmetleri kurar ve çalışıp çalışmadığını test eder. Yönetici izni ister.",
            bg=BG_COLOR,
            fg=TEXT_COLOR,
        )
        info.pack(anchor=tk.W)

        status_row = tk.Frame(body, bg=BG_COLOR)
        status_row.pack(fill=tk.X, pady=(6, 0))

        tk.Label(status_row, text="Hizmet durumu:", bg=BG_COLOR, fg=MUTED_COLOR).pack(side=tk.LEFT)
        self.status_label = tk.Label(
            status_row,
            text="Kontrol ediliyor...",
            bg=STATUS_INFO_BG,
            fg=STATUS_INFO_FG,
            padx=10,
            pady=2,
        )
        self.status_label.pack(side=tk.LEFT, padx=8)

        card = tk.Frame(body, bg=CARD_COLOR, highlightbackground=BORDER_COLOR, highlightthickness=1)
        card.pack(fill=tk.X, pady=(12, 10))

        card_title = tk.Label(
            card,
            text="DNS Seçimi",
            bg=CARD_COLOR,
            fg=TEXT_COLOR,
            font=("Segoe UI", 11, "bold"),
        )
        card_title.pack(anchor=tk.W, padx=12, pady=(12, 6))

        options_row = tk.Frame(card, bg=CARD_COLOR)
        options_row.pack(fill=tk.X, padx=12)

        tk.Label(options_row, text="DNS modu:", bg=CARD_COLOR, fg=MUTED_COLOR).pack(side=tk.LEFT)

        display_choices = ["Otomatik (Önerilen)"] + [p["label"] for p in DNS_PROVIDERS]
        self.choice_combo = ttk.Combobox(
            options_row,
            state="readonly",
            width=38,
            textvariable=self.choice_var,
            values=display_choices,
        )
        self.choice_combo.pack(side=tk.LEFT, padx=8)
        self.choice_combo.set("Otomatik (Önerilen)")

        hint = tk.Label(
            card,
            text="Otomatik mod listedeki DNS'leri sırayla dener ve çalışanı seçer.",
            bg=CARD_COLOR,
            fg=MUTED_COLOR,
        )
        hint.pack(anchor=tk.W, padx=12, pady=(6, 12))

        buttons = tk.Frame(body, bg=BG_COLOR)
        buttons.pack(fill=tk.X, pady=(4, 10))

        self.install_btn = tk.Button(
            buttons,
            text="Kur / Onar",
            command=self._on_install,
            bg=ACCENT_COLOR,
            fg="white",
            activebackground=ACCENT_DARK,
            activeforeground="white",
            relief=tk.FLAT,
            padx=16,
            pady=6,
        )
        self.install_btn.pack(side=tk.LEFT)

        self.uninstall_btn = tk.Button(
            buttons,
            text="Kaldır",
            command=self._on_uninstall,
            bg=UNINSTALL_BG,
            fg=UNINSTALL_FG,
            activebackground=UNINSTALL_ACTIVE_BG,
            activeforeground=UNINSTALL_FG,
            relief=tk.FLAT,
            padx=16,
            pady=6,
        )
        self.uninstall_btn.pack(side=tk.LEFT, padx=8)

        self.open_log_btn = tk.Button(
            buttons,
            text="Günlüğü Aç",
            command=self._open_log,
            bg="#e2e8f0",
            fg=TEXT_COLOR,
            activebackground="#cbd5f5",
            activeforeground=TEXT_COLOR,
            relief=tk.FLAT,
            padx=16,
            pady=6,
        )
        self.open_log_btn.pack(side=tk.LEFT)

        self.busy_label = tk.Label(
            body,
            text="",
            bg=BG_COLOR,
            fg=MUTED_COLOR,
            font=("Segoe UI", 11, "bold"),
            justify="left",
            anchor="w",
            padx=10,
            pady=8,
        )
        self.busy_label.pack(anchor=tk.W, pady=(6, 0))

        log_card = tk.Frame(body, bg=CARD_COLOR, highlightbackground=BORDER_COLOR, highlightthickness=1)
        log_card.pack(fill=tk.BOTH, expand=True)

        log_title = tk.Label(
            log_card,
            text="İşlem Günlüğü",
            bg=CARD_COLOR,
            fg=TEXT_COLOR,
            font=("Segoe UI", 11, "bold"),
        )
        log_title.pack(anchor=tk.W, padx=12, pady=(12, 6))

        self.log_text = tk.Text(
            log_card,
            wrap="word",
            height=12,
            state="disabled",
            bg="#f8fafc",
            fg=TEXT_COLOR,
            bd=0,
            padx=8,
            pady=6,
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        self.choice_combo.configure(state="disabled" if busy else "readonly")
        if self.busy_label is not None:
            if busy:
                stage = self._current_stage or "Başlatılıyor."
                self.busy_label.configure(
                    text=f"İŞLEM DEVAM EDİYOR — LÜTFEN BEKLEYİN\nŞu an: {stage}",
                    bg=BUSY_BG,
                    fg=BUSY_FG,
                )
            else:
                self.busy_label.configure(text="", bg=BG_COLOR, fg=MUTED_COLOR)

    def _set_stage(self, text: str) -> None:
        def apply() -> None:
            self._current_stage = text
            if self.busy_label is not None and self.busy:
                self.busy_label.configure(
                    text=f"İŞLEM DEVAM EDİYOR — LÜTFEN BEKLEYİN\nŞu an: {text}",
                    bg=BUSY_BG,
                    fg=BUSY_FG,
                )

        self.after(0, apply)

    def _set_cancel_mode(self, active: bool) -> None:
        if active:
            self.uninstall_btn.configure(
                text="Durdur ve Kaldır",
                bg=CANCEL_BG,
                fg=CANCEL_FG,
                activebackground=CANCEL_ACTIVE_BG,
                activeforeground=CANCEL_FG,
            )
        else:
            self.uninstall_btn.configure(
                text="Kaldır",
                bg=UNINSTALL_BG,
                fg=UNINSTALL_FG,
                activebackground=UNINSTALL_ACTIVE_BG,
                activeforeground=UNINSTALL_FG,
            )

    def _request_cancel(self) -> None:
        if not self._cancel_event.is_set():
            self._cancel_event.set()
            self._set_stage("İptal isteniyor. Hizmetler kaldırılacak.")
            self._notify("info", "İptal isteği alındı. Kurulum durduruluyor ve kaldırılıyor.")

    def _notify(self, level: str, message: str) -> None:
        def show() -> None:
            if level == "info":
                messagebox.showinfo(APP_NAME, message)
            elif level == "warning":
                messagebox.showwarning(APP_NAME, message)
            else:
                messagebox.showerror(APP_NAME, message)

        self.after(0, show)

    def _apply_status_badge(self, state: str, access_state: str | None) -> None:
        if self.status_label is None:
            return
        if state == "running":
            if access_state == "ok":
                label = "Kurulu • Çalışıyor • Discord erişimi var"
                bg, fg = STATUS_OK_BG, STATUS_OK_FG
            elif access_state == "fail":
                label = "Kurulu • Çalışıyor • Discord erişimi yok"
                bg, fg = STATUS_WARN_BG, STATUS_WARN_FG
            else:
                label = "Kurulu • Çalışıyor"
                bg, fg = STATUS_INFO_BG, STATUS_INFO_FG
        elif state == "stopped":
            label = "Kurulu • Durdurulmuş"
            bg, fg = STATUS_WARN_BG, STATUS_WARN_FG
        elif state == "missing":
            label = "Kurulu değil"
            bg, fg = STATUS_ERR_BG, STATUS_ERR_FG
        else:
            label = "Durum bilinmiyor"
            bg, fg = STATUS_INFO_BG, STATUS_INFO_FG
        self.status_label.configure(text=label, bg=bg, fg=fg)

    def _refresh_status_worker(self) -> None:
        try:
            state, _ = query_service("GoodbyeDPI")
            access_state = self._last_access_state
            if state == "running" and not self.busy:
                ok, _ = test_discord(timeout=STATUS_TEST_TIMEOUT)
                access_state = "ok" if ok else "fail"
                self._last_access_state = access_state
            elif state != "running":
                self._last_access_state = None
                access_state = None
            self.after(0, lambda: self._apply_status_badge(state, access_state))
        finally:
            self._status_check_inflight = False

    def _trigger_status_refresh(self) -> None:
        if self._status_check_inflight:
            return
        self._status_check_inflight = True
        thread = threading.Thread(target=self._refresh_status_worker, daemon=True)
        thread.start()

    def _schedule_status_refresh(self) -> None:
        self._trigger_status_refresh()
        self.after(STATUS_REFRESH_MS, self._schedule_status_refresh)

    def _open_log(self) -> None:
        os.makedirs(APPDATA_BASE, exist_ok=True)
        if not os.path.exists(LOG_PATH):
            with open(LOG_PATH, "w", encoding="utf-8") as handle:
                handle.write("")
        os.startfile(LOG_PATH)

    def _on_install(self) -> None:
        if self.busy:
            self._notify("info", "Şu anda bir işlem devam ediyor. Lütfen bekleyin.")
            return
        self._run_task(self._install_task, "install")

    def _on_uninstall(self) -> None:
        if self.busy:
            if self._current_task == "install":
                self._request_cancel()
                return
            self._notify("info", "Şu anda bir işlem devam ediyor. Lütfen bekleyin.")
            return
        self._run_task(self._uninstall_task, "uninstall")

    def _run_task(self, target, task_name: str) -> None:
        self._current_task = task_name
        if task_name == "install":
            self._cancel_event.clear()
            self._set_cancel_mode(True)
        else:
            self._set_cancel_mode(False)
        self._set_busy(True)
        self._set_stage("Başlatılıyor.")
        thread = threading.Thread(target=target, daemon=True)
        thread.start()

    def _install_task(self) -> None:
        try:
            label = self.choice_var.get().strip()
            choice = "auto"
            if label != "Otomatik (Önerilen)":
                for provider in DNS_PROVIDERS:
                    if provider["label"] == label:
                        choice = provider["id"]
                        break
            result = install_auto(
                choice,
                status_cb=self._set_stage,
                cancel_event=self._cancel_event,
            )
            if result == INSTALL_SUCCESS:
                self._last_access_state = "ok"
                self._notify("info", "Kurulum tamamlandı.")
            elif result == INSTALL_CANCELLED:
                self._last_access_state = None
                self._notify("info", "İşlem iptal edildi ve kaldırıldı.")
            else:
                self._last_access_state = "fail"
                self._notify("warning", "Kurulum bitti ama test başarılı olmadı. Günlüğe bakın.")
        except Exception as exc:
            log(f"Kurulum hatası: {exc}")
            self._notify("error", f"Kurulum başarısız: {exc}")
        finally:
            self.after(0, lambda: self._set_busy(False))
            self.after(0, lambda: self._set_cancel_mode(False))
            self._current_task = None
            self._cancel_event.clear()
            self.after(0, self._trigger_status_refresh)

    def _uninstall_task(self) -> None:
        try:
            ok = uninstall_only(status_cb=self._set_stage)
            if ok:
                self._notify("info", "Kaldırma tamamlandı.")
        except Exception as exc:
            log(f"Kaldırma hatası: {exc}")
            self._notify("error", f"Kaldırma başarısız: {exc}")
        finally:
            self.after(0, lambda: self._set_busy(False))
            self.after(0, lambda: self._set_cancel_mode(False))
            self._current_task = None
            self._cancel_event.clear()
            self._last_access_state = None
            self.after(0, self._trigger_status_refresh)

    def _process_logs(self) -> None:
        try:
            while True:
                line = log_queue.get_nowait()
                self.log_text.configure(state="normal")
                self.log_text.insert(tk.END, line + "\n")
                self.log_text.configure(state="disabled")
                self.log_text.see(tk.END)
        except queue.Empty:
            pass
        self.after(120, self._process_logs)


def run_cli(mode: str, choice: str) -> int:
    if mode == "install":
        result = install_auto(choice)
        if result == INSTALL_SUCCESS:
            return 0
        if result == INSTALL_CANCELLED:
            return 1
        return 2
    if mode == "uninstall":
        uninstall_only()
        return 0
    if mode == "test":
        ok, detail = test_discord()
        print(detail)
        return 0 if ok else 3
    return 1


def main() -> int:
    mode = "gui"
    choice = "auto"
    choice_flags = {"--auto": "auto"}
    for provider in DNS_PROVIDERS:
        choice_flags[f"--{provider['id']}"] = provider["id"]

    for arg in sys.argv[1:]:
        arg = arg.lower()
        if arg in {"--install", "--uninstall", "--test"}:
            mode = arg.lstrip("-")
        if arg in choice_flags:
            choice = choice_flags[arg]

    if not is_admin() and "--elevated" not in sys.argv:
        if relaunch_as_admin():
            return 0
        if mode == "gui":
            messagebox.showerror(APP_NAME, "Yönetici izni gerekiyor.")
        return 1

    if mode != "gui":
        return run_cli(mode, choice)

    app = DiscordErisimApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
