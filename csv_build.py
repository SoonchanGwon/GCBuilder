# -*- coding: utf-8 -*-
"""
csv_build.py  -  수행평가 CSV -> '별명 검색 전용' 프로그램 생성기

사용법
  1) GUI 로 사용 :  python csv_build.py
       [CSV 열기] -> 표로 내용 확인 -> 과목명 입력 -> [CONVERT] -> 검색 프로그램(.py) 저장
  2) 명령줄 사용 :  python csv_build.py aa.csv            -> 과목명을 물어본 뒤 aa_search.py 생성
                    python csv_build.py aa.csv -s 빅데이터분석 -o 결과.py
  * 입력한 과목명이 생성된 검색 프로그램의 창 이름이 됩니다.
  (CSV 를 지정하고 GUI 로 열고 싶으면: python csv_build.py aa.csv --gui)

규칙
  - CSV 첫 행 = 열이름. 열이름이 정확히 "별명" 인 열로 검색합니다.
  - 열이름에 "세특" 이 들어간 열은 자동 줄바꿈으로 표시합니다
    (없으면 마지막 열).
  - 총점과 세특 사이 등에 열이 몇 개 더 있어도 첫 행을 보고 자동 판단합니다.

보안 방식
  - 생성된 프로그램에는 CSV 의 모든 내용이 들어 있지만, 각 학생의 행은
    '그 학생의 별명'에서 만든 키(PBKDF2-SHA256)로 암호화되어 있습니다.
    별명을 정확히 입력해야만 그 행이 복호화되므로, 검색 외의 방법
    (파일 열기, 코드 분석 등)으로는 내용을 볼 수 없습니다.
  - 열이름도 각 학생 데이터와 함께 암호화되어 검색 결과에만 나타납니다.
  - 생성된 .py 파일 자체도 압축·XOR·Base85 로 난독화됩니다.
  - 표준 라이브러리만 사용합니다 (추가 설치 불필요).
"""
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import random
import secrets
import sys
import unicodedata
import zlib

KEY_COLUMN = "별명"
WRAP_KEYWORD = "세특"
PBKDF2_ITER = 120_000
ENCODINGS = ("utf-8-sig", "cp949", "euc-kr", "utf-16")


# --------------------------------------------------------------------------
# 1. CSV 읽기
# --------------------------------------------------------------------------
def read_csv(path):
    """CSV 를 읽어 (header, rows, encoding) 반환. 한글 인코딩 자동 판별."""
    with open(path, "rb") as f:
        raw = f.read()
    last_err = None
    for enc in ENCODINGS:
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError as e:
            last_err = e
    else:
        raise ValueError(f"CSV 인코딩을 판별할 수 없습니다: {last_err}")
    text = text.lstrip("﻿")
    rows = [r for r in csv.reader(io.StringIO(text, newline=""))]
    rows = [r for r in rows if any(c.strip() for c in r)]  # 빈 줄 제거
    if not rows:
        raise ValueError("CSV 가 비어 있습니다.")
    header = [h.strip() for h in rows[0]]
    body = []
    for r in rows[1:]:
        r = [c.strip() for c in r]
        if len(r) < len(header):
            r += [""] * (len(header) - len(r))
        body.append(r[: len(header)])
    return header, body, enc


def norm(s):
    return unicodedata.normalize("NFC", s).strip()


def key_index(header):
    for i, h in enumerate(header):
        if norm(h) == KEY_COLUMN:
            return i
    raise ValueError(f'첫 행에 "{KEY_COLUMN}" 열이 없습니다. 열이름: {header}')


def wrap_indexes(header):
    idx = [i for i, h in enumerate(header) if WRAP_KEYWORD in h]
    return idx or [len(header) - 1]


# --------------------------------------------------------------------------
# 2. 암호화 (생성될 프로그램의 _derive / _lookup 과 반드시 같아야 함)
# --------------------------------------------------------------------------
def _derive(nick, salt, it):
    dk = hashlib.pbkdf2_hmac("sha256", norm(nick).encode("utf-8"), salt, it, 32)
    return hashlib.sha256(b"id" + dk).hexdigest()[:32], hashlib.sha256(b"ek" + dk).digest()


def _xor(data, key):
    return (int.from_bytes(data, "big") ^ int.from_bytes(key, "big")).to_bytes(len(data), "big")


def _encrypt(payload, ek):
    pt = zlib.compress(json.dumps(payload, ensure_ascii=False).encode("utf-8"), 9)
    nonce = secrets.token_bytes(16)
    ct = _xor(pt, hashlib.shake_256(ek + nonce).digest(len(pt)))
    tag = hmac.new(ek, nonce + ct, hashlib.sha256).digest()[:16]
    return base64.b64encode(nonce + tag + ct).decode("ascii")


def build_db(header, rows, progress=None):
    ki = key_index(header)
    groups, skipped = {}, 0
    for r in rows:
        nick = norm(r[ki])
        if not nick:
            skipped += 1
            continue
        groups.setdefault(nick, []).append(r)
    salt = secrets.token_bytes(16)
    db = {}
    total = len(groups)
    for n, (nick, rs) in enumerate(groups.items(), 1):
        rid, ek = _derive(nick, salt, PBKDF2_ITER)
        db[rid] = _encrypt({"h": header, "r": rs}, ek)
        if progress:
            progress(n, total)
    # 학생 수를 숨기기 위한 가짜 항목
    sizes = [len(v) for v in db.values()] or [400]
    for _ in range(random.randint(5, 15) + total // 5):
        db[secrets.token_hex(16)] = base64.b64encode(
            secrets.token_bytes(random.choice(sizes) * 3 // 4 + random.randint(-40, 40))).decode()
    items = list(db.items())
    random.shuffle(items)
    dup = {k: len(v) for k, v in groups.items() if len(v) > 1}
    return dict(items), salt, {"students": total, "skipped": skipped, "dup": dup}


# --------------------------------------------------------------------------
# 3. 생성될 검색 프로그램 본체
# --------------------------------------------------------------------------
RUNTIME = r'''# -*- coding: utf-8 -*-
import base64, hashlib, hmac, json, zlib, unicodedata, sys
import tkinter as tk
from tkinter import ttk, messagebox
import tkinter.font as tkfont

_TITLE = @@TITLE@@
_KEYNAME = @@KEYNAME@@
_WRAPKW = @@WRAPKW@@
_SALT = base64.b64decode(@@SALT@@)
_ITER = @@ITER@@
_DB = @@DATA@@


def _norm(s):
    return unicodedata.normalize("NFC", s).strip()


def _derive(nick):
    dk = hashlib.pbkdf2_hmac("sha256", _norm(nick).encode("utf-8"), _SALT, _ITER, 32)
    return hashlib.sha256(b"id" + dk).hexdigest()[:32], hashlib.sha256(b"ek" + dk).digest()


def _lookup(nick):
    if not _norm(nick):
        return None
    rid, ek = _derive(nick)
    blob = _DB.get(rid)
    if blob is None:
        return None
    raw = base64.b64decode(blob)
    nonce, tag, ct = raw[:16], raw[16:32], raw[32:]
    if not hmac.compare_digest(hmac.new(ek, nonce + ct, hashlib.sha256).digest()[:16], tag):
        return None
    ks = hashlib.shake_256(ek + nonce).digest(len(ct))
    pt = (int.from_bytes(ct, "big") ^ int.from_bytes(ks, "big")).to_bytes(len(ct), "big")
    try:
        return json.loads(zlib.decompress(pt).decode("utf-8"))
    except Exception:
        return None


def _family(root):
    fams = set(tkfont.families(root))
    for f in ("맑은 고딕", "Malgun Gothic", "Apple SD Gothic Neo", "AppleGothic",
              "나눔고딕", "NanumGothic", "Noto Sans CJK KR", "Noto Sans KR", "UnDotum"):
        if f in fams:
            return f
    return tkfont.nametofont("TkDefaultFont").actual("family")


BORDER = "#b9c3d1"
HEAD_BG = "#e6edf7"
CELL_BG = "#ffffff"
PAD = 16
CAP = 170          # 일반 열 최대 너비(px)
MIN_WRAP = 260     # 세특 열 최소 너비(px)


class App:
    def __init__(self, root):
        self.root = root
        self.data = None
        self._lastw = 0
        self._job = None
        root.title(_TITLE)
        sw = root.winfo_screenwidth()
        w = min(1024, sw)
        root.geometry(f"{w}x720+{max((sw - w) // 2, 0)}+40")
        root.minsize(700, 400)
        fam = _family(root)
        self.f = tkfont.Font(root, family=fam, size=11)
        self.fb = tkfont.Font(root, family=fam, size=11, weight="bold")

        top = tk.Frame(root, padx=12, pady=10)
        top.pack(fill="x")
        tk.Label(top, text=_KEYNAME, font=self.fb).pack(side="left")
        self.var = tk.StringVar()
        ent = tk.Entry(top, textvariable=self.var, font=self.f, width=28)
        ent.pack(side="left", padx=8, ipady=3)
        ent.bind("<Return>", lambda e: self.search())
        ent.focus_set()
        tk.Button(top, text="검색", font=self.f, width=8, command=self.search).pack(side="left")
        self.msg = tk.Label(top, text=f"{_KEYNAME}을(를) 정확히 입력하고 검색하세요.", font=self.f, fg="#555")
        self.msg.pack(side="left", padx=12)

        box = tk.Frame(root)
        box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.cv = tk.Canvas(box, highlightthickness=0, bg="white")
        sb = ttk.Scrollbar(box, orient="vertical", command=self.cv.yview)
        self.cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.cv.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.cv, bg="white")
        self.win = self.cv.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda e: self._region())
        self.cv.bind("<Configure>", self._resized)
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            root.bind_all(seq, self._wheel)

    # ---------------- 검색 ----------------
    def search(self):
        q = self.var.get()
        if not _norm(q):
            self._fail(f"{_KEYNAME}을(를) 입력하세요.")
            return
        self.root.config(cursor="watch")
        self.root.update_idletasks()
        res = _lookup(q)
        self.root.config(cursor="")
        if res is None:
            self._fail(f"오류: '{_norm(q)}' 와(과) 정확히 일치하는 {_KEYNAME}이(가) 없습니다.")
            return
        self.data = res
        n = len(res["r"])
        self.msg.config(text=f"'{_norm(q)}' 검색 결과 {n}건", fg="#1a6b2f")
        self._render()
        self.cv.yview_moveto(0)

    def _fail(self, text):
        self.data = None
        self._render()
        self.msg.config(text=text, fg="#c0392b")
        messagebox.showerror(_TITLE, text)

    # ---------------- 표 그리기 ----------------
    def _fit(self, txt, width):
        if self.f.measure(txt) <= width:
            return txt
        lo, hi = 0, len(txt)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.f.measure(txt[:mid] + "…") <= width:
                lo = mid
            else:
                hi = mid - 1
        return txt[:lo] + "…"

    def _render(self):
        for w in self.inner.winfo_children():
            w.destroy()
        if not self.data:
            self._region()
            return
        header = self.data["h"]
        n = len(header)
        rows = [(list(r) + [""] * n)[:n] for r in self.data["r"]]
        wrap = [i for i, h in enumerate(header) if _WRAPKW in h] or [n - 1]
        avail = max(self.cv.winfo_width(), 600) - 14 - (n + 1)
        widths = [0] * n
        for i in range(n):
            if i not in wrap:
                m = max([self.fb.measure(header[i])] + [self.f.measure(r[i]) for r in rows])
                widths[i] = min(m + PAD, CAP)
        rest = avail - sum(widths)
        for i in wrap:
            widths[i] = max(MIN_WRAP, rest // len(wrap))
        tbl = tk.Frame(self.inner, bg=BORDER)
        tbl.pack(anchor="nw")
        for i, w in enumerate(widths):
            tbl.grid_columnconfigure(i, minsize=w)
        for i, h in enumerate(header):
            tk.Label(tbl, text=h, font=self.fb, bg=HEAD_BG, wraplength=widths[i] - PAD,
                     padx=PAD // 2, pady=6, justify="center").grid(
                row=0, column=i, sticky="nsew", padx=(1, 1 if i == n - 1 else 0), pady=(1, 0))
        for ri, r in enumerate(rows, 1):
            last = ri == len(rows)
            for i in range(n):
                if i in wrap:
                    lb = tk.Label(tbl, text=r[i], font=self.f, bg=CELL_BG, justify="left",
                                  anchor="nw", wraplength=widths[i] - PAD - 6, padx=PAD // 2, pady=6)
                else:
                    lb = tk.Label(tbl, text=self._fit(r[i], widths[i] - PAD), font=self.f,
                                  bg=CELL_BG, anchor="center", padx=PAD // 2, pady=6)
                lb.grid(row=ri, column=i, sticky="nsew",
                        padx=(1, 1 if i == n - 1 else 0), pady=(1, 1 if last else 0))
        self._region()

    def _region(self):
        self.inner.update_idletasks()
        w = max(self.inner.winfo_reqwidth(), self.cv.winfo_width())
        h = max(self.inner.winfo_reqheight(), self.cv.winfo_height())
        self.cv.configure(scrollregion=(0, 0, w, h))

    def _resized(self, e):
        if abs(e.width - self._lastw) > 4:
            self._lastw = e.width
            if self._job:
                self.root.after_cancel(self._job)
            self._job = self.root.after(120, self._render)
        else:
            self._region()

    def _wheel(self, e):
        if self.inner.winfo_reqheight() <= self.cv.winfo_height():
            return
        if getattr(e, "num", 0) == 4:
            d = -1
        elif getattr(e, "num", 0) == 5:
            d = 1
        else:
            d = -1 if e.delta > 0 else 1
        self.cv.yview_scroll(d * 3, "units")


def main():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
'''


def make_runtime(db, salt, title):
    src = RUNTIME
    for k, v in {
        "@@TITLE@@": repr(title),
        "@@KEYNAME@@": repr(KEY_COLUMN),
        "@@WRAPKW@@": repr(WRAP_KEYWORD),
        "@@SALT@@": repr(base64.b64encode(salt).decode()),
        "@@ITER@@": str(PBKDF2_ITER),
        "@@DATA@@": repr(db),
    }.items():
        src = src.replace(k, v)
    return src


# --------------------------------------------------------------------------
# 4. 난독화 (파일을 열어도 읽을 수 없게)
# --------------------------------------------------------------------------
def obfuscate(src):
    key = secrets.token_bytes(32)
    packed = zlib.compress(src.encode("utf-8"), 9)
    mixed = bytes(c ^ key[i % len(key)] for i, c in enumerate(packed))
    enc = base64.b85encode(mixed).decode("ascii")
    lines = [enc[i:i + 96] for i in range(0, len(enc), 96)]
    body = "\n".join(f" b'{ln}'" for ln in lines)
    v = ["_" + secrets.token_hex(3) for _ in range(5)]
    return (
        "# -*- coding: utf-8 -*-\n"
        f"import base64 as {v[0]},zlib as {v[1]}\n"
        f"{v[2]}={key!r}\n"
        f"{v[3]}=(\n{body})\n"
        f"{v[4]}={v[0]}.b85decode({v[3]})\n"
        f"exec(compile({v[1]}.decompress(bytes(c^{v[2]}[i%{len(key)}] for i,c in "
        f"enumerate({v[4]}))).decode('utf-8'),'<app>','exec'))\n"
    )


def build(csv_path, out_path=None, progress=None, subject=None):
    header, rows, enc = read_csv(csv_path)
    key_index(header)  # '별명' 열 확인
    stem = os.path.splitext(os.path.basename(csv_path))[0]
    if not out_path:
        out_path = os.path.join(os.path.dirname(os.path.abspath(csv_path)), stem + "_search.py")
    subject = (subject or "").strip()
    title = subject or f"{stem} - {KEY_COLUMN} 검색"
    db, salt, info = build_db(header, rows, progress)
    src = make_runtime(db, salt, title)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(obfuscate(src))
    info.update(out=out_path, encoding=enc, header=header, title=title)
    return info


def summary(info):
    s = [f"생성 완료: {info['out']}",
         f"  창 이름(과목명): {info['title']}",
         f"  CSV 인코딩: {info['encoding']}",
         f"  열이름: {', '.join(info['header'])}",
         f"  검색 가능한 {KEY_COLUMN}: {info['students']}개"]
    if info["skipped"]:
        s.append(f"  ※ {KEY_COLUMN}이 비어 있어 제외된 행: {info['skipped']}개")
    if info["dup"]:
        s.append("  ※ 중복된 " + KEY_COLUMN + "(검색 시 함께 표시): " +
                 ", ".join(f"{k}({v}행)" for k, v in info["dup"].items()))
    return "\n".join(s)


# --------------------------------------------------------------------------
# 5. 생성기 GUI
# --------------------------------------------------------------------------
def run_gui(initial=None):
    import threading
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    import tkinter.font as tkfont

    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    root = tk.Tk()
    root.title("CSV → 별명 검색 프로그램 생성기")
    sw = root.winfo_screenwidth()
    root.geometry(f"{min(1024, sw)}x700+{max((sw - 1024) // 2, 0)}+40")
    fams = set(tkfont.families(root))
    fam = next((f for f in ("맑은 고딕", "Malgun Gothic", "Apple SD Gothic Neo", "AppleGothic",
                            "나눔고딕", "NanumGothic", "Noto Sans CJK KR", "Noto Sans KR")
                if f in fams), None)
    f = tkfont.Font(root, family=fam, size=10) if fam else tkfont.nametofont("TkDefaultFont")
    fb = tkfont.Font(root, family=fam, size=10, weight="bold") if fam else f
    st = ttk.Style(root)
    st.configure("Treeview", font=f, rowheight=f.metrics("linespace") + 8)
    st.configure("Treeview.Heading", font=fb)

    state = {"path": None}
    top = tk.Frame(root, padx=10, pady=8)
    top.pack(fill="x")
    tk.Button(top, text="CSV 열기", font=f, width=10, command=lambda: choose()).pack(side="left")
    conv = tk.Button(top, text="CONVERT", font=fb, width=12, state="disabled",
                     bg="#2d6cdf", fg="white", command=lambda: convert())
    conv.pack(side="left", padx=8)
    tk.Label(top, text="과목명", font=fb).pack(side="left", padx=(8, 4))
    subj = tk.StringVar()
    subj_ent = tk.Entry(top, textvariable=subj, font=f, width=22)
    subj_ent.pack(side="left", ipady=2)
    lbl = tk.Label(top, text="CSV 파일을 열어 주세요.", font=f, anchor="w")
    lbl.pack(side="left", fill="x", expand=True, padx=(10, 0))
    info = tk.Label(root, text="", font=f, fg="#555", anchor="w", padx=10)
    info.pack(fill="x")

    box = tk.Frame(root)
    box.pack(fill="both", expand=True, padx=10, pady=(4, 10))
    tv = ttk.Treeview(box, show="headings")
    vs = ttk.Scrollbar(box, orient="vertical", command=tv.yview)
    hs = ttk.Scrollbar(box, orient="horizontal", command=tv.xview)
    tv.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
    vs.pack(side="right", fill="y")
    hs.pack(side="bottom", fill="x")
    tv.pack(fill="both", expand=True)

    def load(path):
        try:
            header, rows, enc = read_csv(path)
            ki = key_index(header)
        except Exception as e:
            messagebox.showerror("오류", str(e))
            return
        state["path"] = path
        tv.delete(*tv.get_children())
        cols = [f"c{i}" for i in range(len(header))]
        tv["columns"] = cols
        wraps = wrap_indexes(header)
        for i, h in enumerate(header):
            m = max([fb.measure(h)] + [f.measure(r[i]) for r in rows[:200]]) + 20
            w = 480 if i in wraps else min(m, 160)
            tv.heading(cols[i], text=h)
            tv.column(cols[i], width=w, minwidth=40, stretch=(i in wraps), anchor="w" if i in wraps else "center")
        for r in rows:
            tv.insert("", "end", values=[c.replace("\n", " ") for c in r])
        lbl.config(text=os.path.basename(path))
        info.config(text=f"인코딩 {enc} · {len(rows)}행 · 검색 열: '{header[ki]}'({ki + 1}번째) · "
                         f"줄바꿈 열: {', '.join(header[i] for i in wraps)}")
        conv.config(state="normal")

    def choose():
        p = filedialog.askopenfilename(title="CSV 선택", filetypes=[("CSV", "*.csv"), ("모든 파일", "*.*")])
        if p:
            load(p)

    def convert():
        src = state["path"]
        subject = subj.get().strip()
        if not subject:
            messagebox.showerror("오류", "과목명을 입력하세요.\n(생성된 프로그램의 창 이름이 됩니다)")
            subj_ent.focus_set()
            return
        stem = os.path.splitext(os.path.basename(src))[0]
        out = filedialog.asksaveasfilename(
            title="검색 프로그램 저장", defaultextension=".py",
            initialdir=os.path.dirname(os.path.abspath(src)),
            initialfile=stem + "_search.py", filetypes=[("Python", "*.py")])
        if not out:
            return
        conv.config(state="disabled")
        root.config(cursor="watch")
        box_ = {}

        def prog(n, t):
            box_["p"] = (n, t)

        def work():
            try:
                box_["ok"] = build(src, out, prog, subject)
            except Exception as e:
                box_["err"] = e

        th = threading.Thread(target=work, daemon=True)
        th.start()

        def poll():
            if th.is_alive():
                if "p" in box_:
                    info.config(text=f"암호화 중… {box_['p'][0]}/{box_['p'][1]}")
                root.after(100, poll)
                return
            root.config(cursor="")
            conv.config(state="normal")
            if "err" in box_:
                messagebox.showerror("오류", str(box_["err"]))
            else:
                info.config(text=f"완료 → {box_['ok']['out']}")
                messagebox.showinfo("CONVERT 완료", summary(box_["ok"]))

        poll()

    if initial:
        root.after(50, lambda: load(initial))
    root.mainloop()


def main(argv):
    args, out, subject, gui = [], None, None, False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-o" and i + 1 < len(argv):
            out = argv[i + 1]; i += 2; continue
        if a in ("-s", "--subject") and i + 1 < len(argv):
            subject = argv[i + 1]; i += 2; continue
        if a == "--gui":
            gui = True
        elif not a.startswith("-"):
            args.append(a)
        i += 1
    if not args or gui:
        run_gui(args[0] if args else None)
        return
    while not (subject or "").strip():
        try:
            subject = input("과목명을 입력하세요 (생성된 프로그램의 창 이름): ")
        except EOFError:
            print("\n오류: 과목명이 입력되지 않았습니다.")
            sys.exit(1)
    try:
        info = build(args[0], out, lambda n, t: print(f"\r암호화 중… {n}/{t}", end="", flush=True),
                     subject)
        print()
        print(summary(info))
    except Exception as e:
        print(f"\n오류: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
