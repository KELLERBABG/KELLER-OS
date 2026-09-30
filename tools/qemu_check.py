#!/usr/bin/env python3
"""Headless KELLER-OS verification harness.

Boots the kernel under QEMU, captures the COM1 serial log, optionally synthesises real
keyboard and mouse input through QEMU's emulated 8042 (`--type`, `--key`, `--mouse`,
`--click`), optionally captures a graphical framebuffer screendump, then quits the emulator
cleanly over QMP.

Input runs are self-verifying. Before and after the injection the harness asks the guest, over
the serial console, what its own PS/2 counters say, and then requires exactly the traffic it
injected to show up there (`--no-input-check` turns that off). A run that only guards with
`--forbid` can therefore no longer pass because the injection silently did nothing: the guest
has to account for every scancode and packet.

Exit code 0 only when every --expect pattern is present, no --forbid pattern is, and the input
check is green.
"""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

QEMU = os.environ.get("QEMU", r"C:\Program Files\qemu\qemu-system-x86_64.exe")
DEFAULT_IMG = "target/x86_64-sovereign_core/debug/sovereign-core"
# A scripted line is resent once if the guest does not echo it; probes like `crypto` or
# `selftest` can take seconds under TCG, so the wait is generous.
SCRIPT_ACK_TIMEOUT = 15.0
# Delay between the bytes of a scripted line. A burst lands in the emulated UART's 16-byte FIFO
# while the guest may be busy for seconds inside a self-test, and whatever does not fit is dropped
# without a trace - which shows up as a command that ran with characters missing, or as two lines
# merged into one. Dribbling costs milliseconds and removes that whole failure mode.
SCRIPT_KEY_DELAY = 0.002
# The shell's line buffer, so a retry can erase whatever the guest is holding. Keep in step with
# `LINE_CAPACITY` in src/shell.rs.
SCRIPT_LINE_CAPACITY = 96


def qmp_connect(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1.0)
            s.settimeout(5.0)
            s.recv(65536)  # greeting
            s.sendall(b'{"execute":"qmp_capabilities"}\n')
            s.recv(65536)
            return s
        except OSError:
            time.sleep(0.1)
    return None


def qmp(sock, command, **args):
    payload = {"execute": command}
    if args:
        payload["arguments"] = args
    sock.sendall((json.dumps(payload) + "\n").encode())
    buf = b""
    deadline = time.time() + 5.0
    while time.time() < deadline:
        buf += sock.recv(65536)
        for line in buf.split(b"\n"):
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if "return" in msg or "error" in msg:
                return msg
    return {"error": "timeout"}


# Characters that need Shift on a US layout: value is the unshifted key to hold shift with.
SHIFTED = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7",
    "*": "8", "(": "9", ")": "0", "_": "minus", "+": "equal", "{": "bracket_left",
    "}": "bracket_right", "|": "backslash", ":": "semicolon", '"': "apostrophe",
    "<": "comma", ">": "dot", "?": "slash", "~": "grave_accent",
}

# Punctuation QEMU names differently from ASCII.
NAMED = {
    " ": "spc", "\n": "ret", "\r": "ret", "\t": "tab", "\b": "backspace",
    ".": "dot", ",": "comma", "-": "minus", "=": "equal", "/": "slash",
    ";": "semicolon", "'": "apostrophe", "[": "bracket_left",
    "]": "bracket_right", "\\": "backslash", "`": "grave_accent",
}


def normalize_argv(argv):
    r"""Rewrites `--mouse -340,100` into `--mouse=-340,100`.

    argparse only accepts a leading `-` for a value when it looks like a plain negative
    number, so a motion vector would otherwise be read as another option. Doing this here
    keeps the natural spelling working from any shell.
    """
    options = ("--mouse", "--click", "--type", "--key", "--wheel")
    result = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if (
            token in options
            and index + 1 < len(argv)
            and argv[index + 1].startswith("-")
            and not argv[index + 1].startswith("--")
        ):
            result.append(f"{token}={argv[index + 1]}")
            index += 2
            continue
        result.append(token)
        index += 1
    return result


def expand_escapes(text):
    r"""Turns `\n`, `\r`, `\t`, `\b` and `\\` in --type into the characters they name.

    Written out by hand rather than with `codecs.decode`: a command line may legitimately
    contain other backslashes (Windows paths, shell quoting) and silently eating them would
    mistype the guest's input.
    """
    result = []
    index = 0
    while index < len(text):
        character = text[index]
        if character == "\\" and index + 1 < len(text):
            following = text[index + 1]
            mapped = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "\\": "\\"}.get(following)
            if mapped is not None:
                result.append(mapped)
                index += 2
                continue
        result.append(character)
        index += 1
    return "".join(result)


def key_chord(character):
    """QEMU qcodes to press together for one character (empty when unsupported)."""
    if character.isalpha():
        return [character.lower()]
    if character.isdigit():
        return [character]
    if character in SHIFTED:
        return ["shift", SHIFTED[character]]
    if character in NAMED:
        return [NAMED[character]]
    return []


def report_qmp(res, what):
    """Surfaces a rejected QMP input command instead of silently injecting nothing."""
    if isinstance(res, dict) and "error" in res:
        print(f"harness: {what} rejected: {res['error']}", file=sys.stderr)
    return res


def send_chord(sock, codes, hold_ms=40):
    """Presses (and releases) one chord through the emulated 8042."""
    if not codes:
        return
    keys = [{"type": "qcode", "data": code} for code in codes]
    return report_qmp(
        qmp(sock, "send-key", keys=keys, **{"hold-time": hold_ms}),
        f"send-key {'+'.join(codes)}",
    )


def send_mouse(sock, dx, dy):
    """Relative pointer motion through the emulated mouse port."""
    events = []
    if dx:
        events.append({"type": "rel", "data": {"axis": "x", "value": int(dx)}})
    if dy:
        events.append({"type": "rel", "data": {"axis": "y", "value": int(dy)}})
    if not events:
        return None
    return report_qmp(qmp(sock, "input-send-event", events=events), "input-send-event")


def send_click(sock, button="left", hold_ms=60):
    """Presses and releases a pointer button at the current position."""
    down = {"type": "btn", "data": {"down": True, "button": button}}
    up = {"type": "btn", "data": {"down": False, "button": button}}
    res = report_qmp(qmp(sock, "input-send-event", events=[down]), f"{button} down")
    time.sleep(hold_ms / 1000.0)
    report_qmp(qmp(sock, "input-send-event", events=[up]), f"{button} up")
    return res


def send_wheel(sock, notches, step_ms=90):
    """Wheel notches through the emulated mouse. Positive is up, the InputEvent convention.

    One notch per press/release pair, with a pause between them: the emulated device batches
    whatever arrives before its next report, and a batch of three notches would be one packet
    where the guest's counter expects three.
    """
    button = "wheel-up" if notches > 0 else "wheel-down"
    last = None
    for _ in range(abs(notches)):
        down = {"type": "btn", "data": {"down": True, "button": button}}
        up = {"type": "btn", "data": {"down": False, "button": button}}
        last = report_qmp(qmp(sock, "input-send-event", events=[down, up]), f"{button}")
        time.sleep(step_ms / 1000.0)
    return last


# The `input` shell command prints this block, and the harness reads it back as the guest's own
# account of what the emulated 8042 delivered. The keyboard and mouse lines exist with or
# without a display server; the routing and pointer lines only exist when the display server is
# up, so those checks are skipped on a serial-only machine instead of failing.
COUNTER_ACK = "[PS2] keyboard:"
COUNTER_PATTERNS = {
    "keyboard": re.compile(
        r"\[PS2\] keyboard: bytes=(\d+) decoded=(\d+) releases=(\d+) ignored=(\d+) "
        r"queue=(\d+)/(\d+) lost=(\d+)"
    ),
    "mouse": re.compile(
        r"\[PS2\] mouse: bytes=(\d+) packets=(\d+) rejected=(\d+) wheel=(\d+) "
        r"queue=(\d+)/(\d+) lost=(\d+)"
    ),
    "routing": re.compile(r"\[GUI\] input: keys routed=(\d+) refused=(\d+) characters=(\d+)"),
    "pointer": re.compile(
        r"\[GUI\] pointer: cursor=(-?\d+),(-?\d+) packets=(\d+) clicks=(\d+) "
        r"motion=(-?\d+),(-?\d+) buttons=0x([0-9a-fA-F]+)"
    ),
}
# The `input` block's scroll line, which is where a wheel notch arriving from the device turns
# into a moved view: the notch count is the router's own, the gesture count is how many scrolls
# changed something, and "B of M lines back" is the view the focused window is showing.
WHEEL_SCROLL = re.compile(
    r"\[GUI\] scroll: wheel-notches=(-?\d+) gestures=(\d+) keys-to-tiles=(\d+) \| "
    r"(.+?) (\d+) of (\d+) lines back"
)

COUNTER_FIELDS = {
    "keyboard": ("bytes", "decoded", "releases", "ignored", "queued", "capacity", "lost"),
    "mouse": ("bytes", "packets", "rejected", "wheel", "queued", "capacity", "lost"),
    "routing": ("routed", "refused", "characters"),
    "pointer": ("cursor_x", "cursor_y", "packets", "clicks", "motion_x", "motion_y", "buttons"),
}


# The guest's heartbeat, printed from its idle loop every few seconds. It can land *inside* the
# echo of a line this harness has just typed, in which case the log shows the command split in
# two by a `[hb]` run and its halves on either side of it: `nic prob[hb] uptime 5060 ms, ...`
# then `e`. A line comparison then matches neither half, and a line that was delivered and ran
# is reported as keystrokes that never arrived.
HEARTBEAT = re.compile(r"\[hb\][^\n]*\n?")


def without_heartbeats(text):
    """The console text with the guest's heartbeat lines removed.

    Removing the whole run matters, not just its text: the newline that ends it belongs to the
    heartbeat, so an echo that straddles it is one line once that newline goes with it.
    """
    return HEARTBEAT.sub("", text)


def echoed(text, command):
    """How many times the guest's console has echoed this exact command line."""
    return sum(
        1 for line in without_heartbeats(text).splitlines() if line.strip("\r") == command
    )


def parse_counters(text):
    """The last reading of every counter group the `input` command prints."""
    counters = {}
    for group, pattern in COUNTER_PATTERNS.items():
        matches = pattern.findall(text)
        if not matches:
            continue
        values = []
        for index, value in enumerate(matches[-1]):
            if group == "pointer" and index == 6:
                values.append(int(value, 16))
            else:
                values.append(int(value))
        counters[group] = dict(zip(COUNTER_FIELDS[group], values))
    return counters


def query_counters(proc, text_of, timeout=8.0):
    r"""Types `input` into the guest and waits for the counter block it prints back.

    Returns the serial text as it stood when the block arrived, or None if the guest never
    answered. The query travels on COM1, which the PS/2 counters do not see, so it measures the
    injected traffic and nothing else.
    """
    seen = text_of().count(COUNTER_ACK)
    try:
        proc.stdin.write(b"input\n")
        proc.stdin.flush()
    except (OSError, ValueError):
        return None
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = text_of()
        if text.count(COUNTER_ACK) > seen:
            time.sleep(0.3)  # let the rest of the block (pointer, focus holder) finish printing
            return text_of()
        time.sleep(0.05)
    return None


def injected_key_codes(args):
    """QEMU qcodes the input phase presses: (typed characters, chords).

    Characters this harness cannot type (key_chord returns nothing for them) never reach the
    guest, so they are not counted against it.
    """
    typed = expand_escapes(args.type) if args.type else ""
    typed_codes = sum(len(key_chord(character)) for character in typed)
    chord_codes = sum(len(chord.split("-")) for chord in args.key)
    return typed_codes, chord_codes


def injected_motion(args):
    """The cumulative pointer motion the harness asked for, in QEMU's screen axes."""
    dx = dy = 0
    for step in args.mouse:
        try:
            step_x, step_y = step.split(",")
            dx += int(step_x)
            dy += int(step_y)
        except ValueError:
            continue
    return dx, dy


def input_evidence(args, before, after, text):
    """Compares the guest's counters with what the harness injected.

    Returns (lines, failures): `lines` are printed as the run's evidence, `failures` are counted
    against the exit code. Byte, click and motion counts are exact - the emulated controller
    cannot deliver anything else - while the packet count is a lower bound, because a large
    motion is split across several packets.
    """
    lines = []
    failures = []

    def delta(group, field):
        return after[group][field] - before[group][field]

    if "keyboard" not in before or "keyboard" not in after:
        failures.append(
            "input: the guest never printed its PS/2 counters over COM1, so nothing shows the "
            "injected events arrived"
        )
        return lines, failures

    typed_codes, chord_codes = injected_key_codes(args)
    expected_bytes = 2 * (typed_codes + chord_codes)
    got_bytes = delta("keyboard", "bytes")
    lost = delta("keyboard", "lost")
    verdict = "PASS" if got_bytes == expected_bytes and lost == 0 else "FAIL"
    lines.append(
        f"input: keyboard +{got_bytes} bytes of {expected_bytes} injected, ring lost={lost} - {verdict}"
    )
    if verdict == "FAIL":
        failures.append("input: keyboard byte count does not match the injection")

    if "mouse" in before and "mouse" in after:
        move_events = len(args.mouse)
        packets = delta("mouse", "packets")
        rejected = delta("mouse", "rejected")
        mouse_lost = delta("mouse", "lost")
        verdict = "PASS" if packets >= move_events and rejected == 0 and mouse_lost == 0 else "FAIL"
        lines.append(
            f"input: mouse +{packets} packets for {move_events} motion events, "
            f"rejected={rejected}, ring lost={mouse_lost} - {verdict}"
        )
        if verdict == "FAIL":
            failures.append("input: mouse packet count does not match the injection")

        # The wheel is counted in four-byte packets, not in notches and not signed: a notch down
        # is a wheel byte exactly as much as a notch up is, so a device that never negotiated
        # IntelliMouse mode shows up here as zero rather than as a wrong direction.
        expected_notches = sum(abs(notches) for notches in args.wheel)
        if expected_notches:
            seen = delta("mouse", "wheel")
            verdict = "PASS" if seen == expected_notches else "FAIL"
            lines.append(
                f"input: mouse wheel +{seen} wheel byte(s) for {expected_notches} injected "
                f"notch(es) - {verdict}"
            )
            if verdict == "FAIL":
                failures.append(
                    "input: wheel byte count does not match the injection (the guest may not "
                    "have negotiated IntelliMouse mode - check its `[--] PS/2 MOUSE WHEEL` line)"
                )

        # A device byte is not a scrolled view: this reads the router's own account of the same
        # notches, and the view it left the focused window showing. Up-notches only, because a
        # notch down from the live tail has nothing to move and would make this a test of the
        # clamp instead of the scroll.
        up_notches = sum(notches for notches in args.wheel if notches > 0)
        if up_notches:
            readings = WHEEL_SCROLL.findall(text)
            if not readings:
                failures.append(
                    "input: the guest printed no `[GUI] scroll:` line, so nothing shows the "
                    "wheel reached the display server"
                )
            else:
                notches, gestures, _, title, back, total = readings[-1]
                ok = int(notches) == up_notches and int(gestures) >= 1 and int(back) > 0
                lines.append(
                    f"input: router saw {notches} wheel notch(es), {gestures} gesture(s); "
                    f"{title} is {back} of {total} lines back - {'PASS' if ok else 'FAIL'}"
                )
                if not ok:
                    failures.append(
                        "input: the wheel notch did not move a backscroll view (the window under "
                        "the pointer may have no history, or the pointer is not over a window)"
                    )

    move_x, move_y = injected_motion(args)

    if "pointer" in before and "pointer" in after:
        clicks = delta("pointer", "clicks")
        verdict = "PASS" if clicks == len(args.click) else "FAIL"
        lines.append(f"input: clicks +{clicks} of {len(args.click)} injected - {verdict}")
        if verdict == "FAIL":
            failures.append("input: click count does not match the injection")

        # `motion` is the raw PS/2 delta, so a downward screen motion reads as a negative value
        # there and the sign flips against the value the harness injected.
        raw = (delta("pointer", "motion_x"), delta("pointer", "motion_y"))
        expected_raw = (move_x, -move_y)
        verdict = "PASS" if raw == expected_raw else "FAIL"
        lines.append(
            f"input: motion +{raw[0]},{raw[1]} of +{expected_raw[0]},{expected_raw[1]} injected "
            f"(PS/2 +y is up) - {verdict}"
        )
        if verdict == "FAIL":
            failures.append("input: cumulative motion does not match the injection")

        from_x = before["pointer"]["cursor_x"]
        from_y = before["pointer"]["cursor_y"]
        to_x = after["pointer"]["cursor_x"]
        to_y = after["pointer"]["cursor_y"]
        target = (from_x + move_x, from_y + move_y)
        mode = re.search(r"\[FB\] (\d+)x(\d+)x32", text)
        on_screen = bool(mode) and 0 <= target[0] < int(mode.group(1)) and 0 <= target[1] < int(mode.group(2))
        if on_screen:
            verdict = "PASS" if (to_x, to_y) == target else "FAIL"
            lines.append(
                f"input: cursor {from_x},{from_y} -> {to_x},{to_y} "
                f"(expected {target[0]},{target[1]}) - {verdict}"
            )
            if verdict == "FAIL":
                failures.append("input: cursor did not move by the injected delta")
        else:
            lines.append(
                f"input: cursor {from_x},{from_y} -> {to_x},{to_y}, landing point "
                f"{target[0]},{target[1]} is off-screen so the exact check is skipped - NOTE"
            )

    if "routing" in before and "routing" in after:
        routed = delta("routing", "routed")
        refused = delta("routing", "refused")
        characters = delta("routing", "characters")
        lines.append(
            f"input: routing +{routed} routed, +{refused} refused, +{characters} characters "
            f"delivered - NOTE"
        )
        # Typed text always reaches the routing layer, delivered or refused; a modifier-only
        # chord legitimately does not, which is why only typed characters are held to this.
        if typed_codes and routed + refused == 0:
            failures.append(
                "input: no keystroke reached the routing layer, so the focus gate was never exercised"
            )

    return lines, failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--img", default=DEFAULT_IMG)
    ap.add_argument("--secs", type=float, default=6.0, help="how long to let the guest run")
    ap.add_argument("--port", type=int, default=4477)
    ap.add_argument("--expect", action="append", default=[], help="substring that must appear on serial")
    ap.add_argument("--forbid", action="append", default=[], help="substring that must NOT appear")
    ap.add_argument("--serial-out", default="target/serial.log")
    ap.add_argument("--screendump", default=None, help="path for a PPM framebuffer capture")
    ap.add_argument("--display", default="none", help="QEMU -display value; use 'sdl'/'gtk' for a window")
    ap.add_argument("--vga", default=None, help="e.g. 'std' to attach a VGA adapter")
    ap.add_argument("--stdin-script", default=None,
                    help="file whose bytes are typed into the guest serial console")
    ap.add_argument("--stdin-delay", type=float, default=2.0)
    ap.add_argument("--show-log", action="store_true", help="always print the serial log")
    ap.add_argument("--type", default=None,
                    help=r"text typed through the emulated PS/2 keyboard; \n is Return")
    ap.add_argument("--key", action="append", default=[],
                    help="one chord, e.g. 'alt-tab' or 'ret'; repeatable, sent first")
    ap.add_argument("--mouse", action="append", default=[],
                    help="relative pointer motion as 'dx,dy' (QEMU screen axes: +dy is "
                         "down, which the emulated mouse reports as an upward PS/2 delta); "
                         "repeatable, sent after chords. A negative dx/dy needs the '=' "
                         "form, e.g. --mouse=-400,0, or argparse reads it as another option")
    ap.add_argument("--click", action="append", default=[],
                    help="a button press at the current position, e.g. 'left'; repeatable, "
                         "interleaved with --mouse in the order given")
    ap.add_argument("--wheel", action="append", default=[], type=int,
                    help="wheel notches through the emulated mouse, 'n' for n up and '-n' for "
                         "n down; repeatable, sent after --type (one notch per event, so the "
                         "guest counts one wheel byte each). Requires "
                         "the guest to have negotiated IntelliMouse mode at bring-up - a "
                         "three-byte device has no wheel byte for QEMU to put them in")
    ap.add_argument("--input-delay", type=float, default=1.0,
                    help="pause before the input phase starts")
    ap.add_argument("--input-settle", type=float, default=1.5,
                    help="pause after the input phase, before the screendump")
    ap.add_argument("--input-check", action=argparse.BooleanOptionalAction, default=True,
                    help="ask the guest for its PS/2 counters before and after the injection and "
                         "require exactly the injected traffic to show up in them (default: on "
                         "whenever input is injected; --no-input-check skips it)")
    ap.add_argument("--qemu-arg", action="append", default=[],
                    help="one extra QEMU argument, repeatable (e.g. --qemu-arg=-machine "
                         "--qemu-arg=pc,i8042=off to run the guest without a PS/2 controller: "
                         "the guest says `[--] PS/2 CONTROLLER ABSENT` once, counts no bytes "
                         "at all, and the input checks then fail as they should). i8042=off is "
                         "the only PS/2 switch QEMU has: it drops both ports, so a controller "
                         "that answers with a dead keyboard or no mouse cannot be emulated "
                         "here - the guest reports that case per device at boot ("
                         "`[--] PS/2 DEVICES: ...`), and it needs real hardware to be seen). "
                         "Attaching a disk takes three arguments, e.g. --qemu-arg=-device "
                         "--qemu-arg=ich9-ahci,id=ahci --qemu-arg=-drive "
                         "--qemu-arg=id=vdisk,file=target/vault.img,if=none,format=raw "
                         "--qemu-arg=-device --qemu-arg=ide-hd,drive=vdisk,bus=ahci.0 (see "
                         "README step 7); without it the guest prints "
                         "`[--] STORAGE CONTROLLER: no AHCI controller on bus 0` and the "
                         "vault stays in RAM, which is a documented state rather than a failure)")
    args = ap.parse_args(normalize_argv(sys.argv[1:]))

    if not os.path.exists(args.img):
        print(f"harness: image not found: {args.img}", file=sys.stderr)
        return 2

    serial_abs = os.path.abspath(args.serial_out)
    os.makedirs(os.path.dirname(serial_abs) or ".", exist_ok=True)
    if os.path.exists(serial_abs):
        os.remove(serial_abs)
    # QEMU's -serial driver syntax splits on ':', so a Windows drive letter in an
    # absolute path breaks "file:C:...". Use a path relative to the QEMU cwd instead.
    root = os.path.abspath(".")
    if serial_abs.lower().startswith(root.lower()):
        serial_arg = os.path.relpath(serial_abs, root).replace("\\", "/")
    else:
        serial_arg = serial_abs.replace("\\", "/")

    # `-kernel` boots through QEMU's multiboot ROM: no firmware runs first, so the
    # kernel is entered directly in 32-bit protected mode with the multiboot handoff.
    cmd = [
        QEMU, "-cpu", "max",
        "-m", "256M",
        "-kernel", os.path.abspath(args.img),
        "-no-reboot",
        "-d", "guest_errors,int",
        "-D", os.path.abspath("target/qemu-debug.log"),
        "-qmp", f"tcp:127.0.0.1:{args.port},server,nowait",
    ]
    if args.vga:
        cmd += ["-vga", args.vga]
    # Any injected event needs stdin - not to send it (that goes over QMP) but because the
    # counter queries that prove it arrived are typed on the serial console.
    interactive = bool(args.stdin_script) or bool(
        args.type or args.key or args.mouse or args.click or args.wheel
    )

    if interactive:
        # QEMU reads console input from the same channel it writes to, so the guest can only be
        # typed at when serial is stdio; otherwise the log goes straight to a file.
        cmd += ["-serial", "stdio"]
    else:
        cmd += ["-serial", f"file:{serial_arg}"]
    cmd += ["-display", args.display]
    cmd += args.qemu_arg

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if interactive else subprocess.DEVNULL,
        stdout=subprocess.PIPE if interactive else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    sock = qmp_connect(args.port)
    if sock is None:
        proc.kill()
        print("harness: could not connect to QMP", file=sys.stderr)
        return 2

    # Typed input and serial output share one channel. QEMU writes serial output into the
    # stdout pipe and serves QMP from the same main loop, so the pipe must be drained
    # *while* the guest runs: a Windows pipe holds only a few kilobytes, and a full pipe
    # blocks QEMU in `write` until the QMP socket stops answering.
    captured = bytearray()
    reader = None
    if interactive:
        def drain():
            while True:
                try:
                    # read1, not read: it returns as soon as anything is available, so the
                    # capture is visible to the counter queries while the guest still runs.
                    # read(n) would block until the full n bytes arrived, and on a mostly idle
                    # pipe that means the harness would only see the log at EOF.
                    chunk = proc.stdout.read1(4096)
                except Exception:
                    break
                if not chunk:
                    break
                captured.extend(chunk)

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()

    # stdio runs are captured by the drain thread and written out here; file runs are written by
    # QEMU itself, so only the stdio path has anything to flush.
    capturing_stdout = interactive
    evidence_failures = []

    def serial_text():
        return bytes(captured).decode("utf-8", "replace")

    try:
        if args.stdin_script:
            time.sleep(args.stdin_delay)
            with open(args.stdin_script, "rb") as fh:
                script = fh.read()
            # Drip-feed one line at a time, and require the guest to echo each one before the
            # next goes out. QEMU forwards serial input only as fast as the guest's UART accepts
            # it, so a burst gets truncated - and a scripted command that silently never ran
            # would otherwise look exactly like a command whose output nobody thought to
            # assert. The echo is the receipt: it only appears once the shell has consumed the
            # line, which also keeps at most one line in flight.
            started = time.time()
            for command in (line.strip() for line in script.decode("utf-8", "replace").splitlines()):
                if not command:
                    continue
                acknowledged = False
                for attempt in (1, 2):
                    seen = echoed(serial_text(), command)
                    for byte in command.encode() + b"\n":
                        proc.stdin.write(bytes([byte]))
                        proc.stdin.flush()
                        time.sleep(SCRIPT_KEY_DELAY)
                    deadline = time.time() + SCRIPT_ACK_TIMEOUT
                    while time.time() < deadline:
                        if echoed(serial_text(), command) > seen:
                            acknowledged = True
                            break
                        time.sleep(0.05)
                    if acknowledged:
                        time.sleep(0.1)
                        break
                    print(
                        f"harness: the guest did not echo {command!r}, sending it again",
                        file=sys.stderr,
                    )
                    # A partial line is worse than no line: the guest holds a prefix that the
                    # retry would be appended to, and a mis-typed command that still parses runs
                    # as if it had been intended. Erase the prefix before retrying.
                    proc.stdin.write(b"\x7f" * SCRIPT_LINE_CAPACITY + b"\n")
                    proc.stdin.flush()
                    time.sleep(0.3)
                if not acknowledged:
                    evidence_failures.append(
                        f"script: the guest never echoed the line {command!r}, so that command "
                        f"did not run"
                    )
            remaining = args.secs - args.stdin_delay - (time.time() - started)
            time.sleep(max(0.0, remaining))
            # stdin stays open: the counter queries that prove the injection arrived are typed on
            # this same console, and the emulator is stopped over QMP, not by EOF.
        else:
            time.sleep(args.secs)

        # Input phase: every event below enters the guest through QEMU's emulated 8042, so
        # what the serial log then shows is produced by the kernel's own driver, decoder and
        # focus routing - not by anything this harness asserts. Order is chords, then pointer
        # motion, then text, which is what "switch focus, aim the pointer, type a command"
        # needs; type `\n` inside --type for Return.
        if args.type or args.key or args.mouse or args.click or args.wheel:
            before = None
            if args.input_check:
                baseline = serial_text()
                # COM1 input does not touch the PS/2 counters, so a block a scripted command
                # printed earlier is as good a baseline as a fresh query - ask for one only when
                # nothing has printed it yet.
                if parse_counters(baseline).get("keyboard") is None:
                    baseline = query_counters(proc, serial_text)
                if baseline:
                    before = parse_counters(baseline)
            time.sleep(args.input_delay)
            for chord in args.key:
                send_chord(sock, chord.split("-"))
                time.sleep(0.15)
            # `--mouse` and `--click` alternate one for one: move, click, move, click. That
            # is what "aim at a window, click it, aim at the next one, click it" needs.
            clicks = list(args.click)
            steps = max(len(args.mouse), len(clicks))
            for index in range(steps):
                if index < len(args.mouse):
                    step = args.mouse[index]
                    try:
                        dx_text, dy_text = step.split(",")
                        dx, dy = int(dx_text), int(dy_text)
                    except ValueError:
                        print(
                            f"harness: bad --mouse value {step!r} (want dx,dy)",
                            file=sys.stderr,
                        )
                        dx = dy = 0
                    send_mouse(sock, dx, dy)
                    time.sleep(0.2)
                if index < len(clicks):
                    send_click(sock, clicks[index] or "left")
                    time.sleep(0.2)
            if args.type:
                for character in expand_escapes(args.type):
                    send_chord(sock, key_chord(character))
                    time.sleep(0.06)
            # The wheel comes last, after any typed text: typing in the shell snaps its view back
            # to the live tail, so a scroll injected before it would be undone before the
            # counters are read.
            for notches in args.wheel:
                send_wheel(sock, notches)
            time.sleep(args.input_settle)

            # What the guest says about the traffic it just received. Without this the run could
            # forbid a symptom of input that never arrived and still look green.
            if args.input_check:
                after_text = query_counters(proc, serial_text)
                after = parse_counters(after_text) if after_text else None
                if (before and before.get("keyboard")) and (after and after.get("keyboard")):
                    lines, failures = input_evidence(args, before, after, after_text)
                else:
                    lines, failures = [], [
                        "input: the guest never answered the PS/2 counter query, so nothing shows "
                        "the injected events arrived"
                    ]
                for line in lines:
                    print(line)
                evidence_failures.extend(failures)

        if args.screendump:
            os.makedirs(os.path.dirname(os.path.abspath(args.screendump)) or ".", exist_ok=True)
            res = qmp(sock, "screendump", filename=os.path.abspath(args.screendump))
            if "error" in res:
                print(f"harness: screendump failed: {res['error']}", file=sys.stderr)
            time.sleep(0.4)
    finally:
        qmp(sock, "quit")
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        sock.close()

    if capturing_stdout:
        if reader is not None:
            # QEMU has exited, so the drain loop is about to see EOF; collect the rest.
            reader.join(timeout=5.0)
        with open(serial_abs, "wb") as fh:
            fh.write(bytes(captured))

    text = ""
    if os.path.exists(serial_abs):
        with open(serial_abs, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")

    dbg = os.path.abspath("target/qemu-debug.log")
    dbg_text = ""
    if os.path.exists(dbg) and os.path.getsize(dbg) > 0:
        with open(dbg, "rb") as fh:
            dbg_text = fh.read().decode("utf-8", "replace")

    ok = True
    for needle in args.expect:
        if needle not in text:
            print(f"FAIL missing: {needle!r}")
            ok = False
    for needle in args.forbid:
        if needle in text:
            print(f"FAIL forbidden: {needle!r}")
            ok = False
    for note in evidence_failures:
        print(f"FAIL {note}")
        ok = False

    if args.show_log or not ok:
        print("---- serial ----")
        print(text, end="" if text.endswith("\n") else "\n")
        print("---- end ----")
        if dbg_text and not ok:
            tail = "\n".join(dbg_text.strip().splitlines()[-15:])
            print("---- qemu debug (tail) ----")
            print(tail)

    print("harness: PASS" if ok else "harness: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
