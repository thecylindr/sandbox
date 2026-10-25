"""Small, explicit Win32 bindings. Importable for layout tests; API calls require 64-bit Windows."""
import ctypes as C
import os
import subprocess
import uuid

U8, U16, U32, U64, PTR = C.c_uint8, C.c_uint16, C.c_uint32, C.c_uint64, C.c_void_p


class GUID(C.Structure):
    _fields_ = [("a", U32), ("b", U16), ("c", U16), ("d", U8 * 8)]

    @classmethod
    def parse(cls, value):
        return cls.from_buffer_copy(uuid.UUID(str(value)).bytes_le)


class Blob(C.Structure):
    _fields_ = [("size", U32), ("data", PTR)]


class Display(C.Structure):
    _fields_ = [("name", C.c_wchar_p), ("description", C.c_wchar_p)]


class UnionValue(C.Union):
    _fields_ = [("u8", U8), ("u16", U16), ("u32", U32), ("pointer", PTR), ("double", C.c_double)]


class Value(C.Structure):
    _fields_ = [("type", U32), ("value", UnionValue)]


class Condition(C.Structure):
    _fields_ = [("field", GUID), ("match", U32), ("value", Value)]


class Action(C.Structure):
    _fields_ = [("type", U32), ("key", GUID)]


class Context(C.Union):
    _fields_ = [("raw", U64), ("key", GUID)]


class Filter(C.Structure):
    _fields_ = [("key", GUID), ("display", Display), ("flags", U32), ("provider", PTR),
                ("providerData", Blob), ("layer", GUID), ("sublayer", GUID), ("weight", Value),
                ("count", U32), ("conditions", C.POINTER(Condition)), ("action", Action),
                ("context", Context), ("reserved", PTR), ("id", U64), ("effectiveWeight", Value)]


class Sublayer(C.Structure):
    _fields_ = [("key", GUID), ("display", Display), ("flags", U32), ("provider", PTR),
                ("providerData", Blob), ("weight", U16)]


CONNECT4 = "c38d57d1-05a7-4c33-904f-7fbceee60e82"
CONNECT6 = "4a72393b-319f-44bc-84c3-ba54dcb3b6b4"
RECEIVE4 = "e1cd9fe7-f4b5-4273-96c0-592e487b8650"
RECEIVE6 = "a3b42c97-9f04-4672-b87e-cee9c483257f"
USER_ID = "af043a0a-b34d-4f86-979c-c90371af6e66"
REMOTE_IP = "b235ae9a-1d64-49b8-a44c-5ff3d9095045"
REMOTE_PORT = "c35a604d-d22b-4e1a-91b4-68f674ee674b"
PROTOCOL = "3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"
NAMESPACE = uuid.UUID("97c04e9c-b4fd-4d38-a9c8-b72a06bc75f3")


def filter_specs(port, offline=False):
    """OR is represented by separate blocking filters; every filter also matches the worker SID."""
    if not 1024 <= port <= 65535:
        raise ValueError("invalid proxy port")
    return [("v4-address", CONNECT4, REMOTE_IP, 3, 0x7F000001),
            ("v4-port", CONNECT4, REMOTE_PORT, 2, port),
            ("v4-protocol", CONNECT4, PROTOCOL, 1, 6),
            ("v6", CONNECT6, None, 0, 0), ("in4", RECEIVE4, None, 0, 0),
            ("in6", RECEIVE6, None, 0, 0)] + ([("offline", CONNECT4, None, 0, 0)] if offline else [])


def dll(name):
    if os.name != "nt" or C.sizeof(PTR) != 8:
        raise OSError("native-user requires 64-bit Windows and 64-bit Python")
    return C.WinDLL(name, use_last_error=True)


def function(lib, name, args, result=U32):
    fn = getattr(lib, name)
    fn.argtypes, fn.restype = args, result
    return fn


def checked(ok):
    if not ok:
        raise C.WinError(C.get_last_error())


def status(code):
    if code:
        raise OSError(f"Windows API failed: 0x{code:08x}")


def interface_index(guid):
    lib = dll("iphlpapi")
    key, luid, index = GUID.parse(str(guid).strip("{}")), U64(), U32()
    status(function(lib, "ConvertInterfaceGuidToLuid", [PTR, PTR])(C.byref(key), C.byref(luid)))
    status(function(lib, "ConvertInterfaceLuidToIndex", [PTR, PTR])(C.byref(luid), C.byref(index)))
    return index.value


def protect(data, decrypt=False):
    lib, kernel = dll("crypt32"), dll("kernel32")
    buffer = C.create_string_buffer(data)
    src, out = Blob(len(data), C.cast(buffer, PTR)), Blob()
    if decrypt:
        fn = function(lib, "CryptUnprotectData", [PTR, PTR, PTR, PTR, PTR, U32, PTR])
        checked(fn(C.byref(src), None, None, None, None, 1, C.byref(out)))
    else:
        fn = function(lib, "CryptProtectData", [PTR, C.c_wchar_p, PTR, PTR, PTR, U32, PTR])
        checked(fn(C.byref(src), "AI Sandbox account", None, None, None, 5, C.byref(out)))
    try:
        return C.string_at(out.data, out.size)
    finally:
        function(kernel, "LocalFree", [PTR], PTR)(out.data)


def filters(sid, port, offline=False, remove=False):
    """Persistent per-SID WFP blocks survive launcher crashes. Replaced atomically, never globally."""
    import re
    if not re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-\d+", sid):
        raise ValueError("expected a local account SID")
    lib, adv, kernel = dll("fwpuclnt"), dll("advapi32"), dll("kernel32")
    handle, descriptor, length = PTR(), PTR(), U32()
    checked(function(adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [C.c_wchar_p, U32, PTR, PTR])(
        "D:(A;;0x1;;;" + sid + ")", 1, C.byref(descriptor), C.byref(length)))
    blob = Blob(length.value, descriptor)
    user = Condition(GUID.parse(USER_ID), 0, Value(14, UnionValue(pointer=C.cast(C.pointer(blob), PTR))))
    subkey = GUID.parse(uuid.uuid5(NAMESPACE, sid))
    opened, transaction = False, False
    try:
        status(function(lib, "FwpmEngineOpen0", [C.c_wchar_p, U32, PTR, PTR, PTR])(
            None, 10, None, None, C.byref(handle)))  # RPC_C_AUTHN_WINNT
        opened = True
        status(function(lib, "FwpmTransactionBegin0", [PTR, U32])(handle, 0))
        transaction = True
        if not remove:
            sub = Sublayer(key=subkey, display=Display("AI Sandbox " + sid, None), flags=1, weight=65535)
            result = function(lib, "FwpmSubLayerAdd0", [PTR, PTR, PTR])(handle, C.byref(sub), None)
            if result != 0x80320009:  # FWP_E_ALREADY_EXISTS; key belongs only to this managed SID.
                status(result)
        for label, layer, field, kind, number in filter_specs(port, True):
            key = GUID.parse(uuid.uuid5(NAMESPACE, sid + "/" + label))
            result = function(lib, "FwpmFilterDeleteByKey0", [PTR, PTR])(handle, C.byref(key))
            if result != 0x80320003:  # FWP_E_FILTER_NOT_FOUND
                status(result)
            if remove or label == "offline" and not offline:
                continue
            conditions = [user]
            if field:
                value = UnionValue()
                setattr(value, {1: "u8", 2: "u16", 3: "u32"}[kind], number)
                conditions.append(Condition(GUID.parse(field), 10, Value(kind, value)))  # NOT_EQUAL
            array = (Condition * len(conditions))(*conditions)
            rule = Filter(key=key, display=Display("AI Sandbox " + label, None), flags=1,
                          layer=GUID.parse(layer), sublayer=subkey, count=len(conditions), conditions=array,
                          action=Action(type=0x1001))  # FWP_ACTION_BLOCK
            status(function(lib, "FwpmFilterAdd0", [PTR, PTR, PTR, PTR])(handle, C.byref(rule), None, None))
        if remove:
            result = function(lib, "FwpmSubLayerDeleteByKey0", [PTR, PTR])(handle, C.byref(subkey))
            if result != 0x80320007:  # FWP_E_SUBLAYER_NOT_FOUND
                status(result)
        status(function(lib, "FwpmTransactionCommit0", [PTR])(handle))
        transaction = False
    finally:
        if transaction:
            function(lib, "FwpmTransactionAbort0", [PTR])(handle)
        if opened:
            function(lib, "FwpmEngineClose0", [PTR])(handle)
        function(kernel, "LocalFree", [PTR], PTR)(descriptor)


# Типичные коды CreateProcessWithLogonW: это настройки Windows, а не сбой лаунчера.
LOGON_HINTS = {
    2: "файл программы не найден",
    3: "каталог программы или проекта не найден",
    5: "нет доступа: .exe, его библиотеки и каталог проекта должны быть доступны созданному пользователю (не в профиле владельца)",
    193: "это не программа Windows x64",
    740: "программа требует повышения прав; запускайте обычный CLI агента",
    1058: "служба «Вторичный вход в систему» (seclogon) отключена; задайте ей ручной запуск",
    1326: "неверный пароль учётной записи; выполните remove-user и setup-user заново",
    1327: "ограничения учётной записи (политика паролей или часы входа) запретили вход",
    1331: "учётная запись отключена",
    1385: "политика Windows не разрешает этому пользователю локальный вход (право «Разрешить вход в систему локально»)",
    1909: "учётная запись заблокирована политикой",
}


def logon_error(code):
    try:
        text = str(C.WinError(code))
    except AttributeError:  # не Windows: только тесты
        text = f"CreateProcessWithLogonW, код {code}"
    return OSError(text + (f". {LOGON_HINTS[code]}" if code in LOGON_HINTS else ""))


def environment_block(env):
    """Блок UTF-16: имена по алфавиту без учёта регистра, пары через NUL, в конце два NUL."""
    for key, value in env.items():
        if not key or "=" in key or "\0" in key or "\0" in value:
            raise ValueError(f"Недопустимая переменная окружения: {key!r}")
    return "\0".join(f"{k}={v}" for k, v in sorted(env.items(), key=lambda item: item[0].upper())) + "\0\0"


def command_line(command):
    """Строка команды для CreateProcessWithLogonW; документированный предел — 1024 символа."""
    line = subprocess.list2cmdline(command)
    if len(line) > 1024:
        raise ValueError("Командная строка длиннее 1024 символов: CreateProcessWithLogonW её не принимает. "
                         "Сократите путь/аргументы или вынесите их в файл настроек программы.")
    return line


class Startup(C.Structure):
    _fields_ = [("cb", U32), ("reserved", C.c_wchar_p), ("desktop", C.c_wchar_p), ("title", C.c_wchar_p),
                ("x", U32), ("y", U32), ("xsize", U32), ("ysize", U32), ("xchars", U32), ("ychars", U32),
                ("fill", U32), ("flags", U32), ("show", U16), ("reservedSize", U16), ("reservedData", PTR),
                ("stdin", PTR), ("stdout", PTR), ("stderr", PTR)]


class ProcessInfo(C.Structure):
    _fields_ = [("process", PTR), ("thread", PTR), ("pid", U32), ("tid", U32)]


class BasicLimits(C.Structure):
    _fields_ = [("processTime", C.c_int64), ("jobTime", C.c_int64), ("flags", U32),
                ("minWorking", C.c_size_t), ("maxWorking", C.c_size_t), ("processes", U32),
                ("affinity", C.c_size_t), ("priority", U32), ("scheduling", U32)]


class ExtendedLimits(C.Structure):
    _fields_ = [("basic", BasicLimits), ("io", U64 * 6), ("processMemory", C.c_size_t),
                ("jobMemory", C.c_size_t), ("peakProcess", C.c_size_t), ("peakJob", C.c_size_t)]


class Trustee(C.Structure):
    _fields_ = [("multiple", PTR), ("operation", U32), ("form", U32), ("type", U32), ("name", PTR)]


class ExplicitAccess(C.Structure):
    _fields_ = [("permissions", U32), ("mode", U32), ("inheritance", U32), ("trustee", Trustee)]


class DesktopAccess:
    """Grant this managed SID access to the current desktop, revoke only its ACEs afterwards."""
    EDIT_DACL = 0x60000  # READ_CONTROL | WRITE_DAC: права на сам дескриптор, не на содержимое объекта

    def __init__(self, sid):
        self.adv, self.kernel, self.user = dll("advapi32"), dll("kernel32"), dll("user32")
        self.sid, self.granted = PTR(), []
        checked(function(self.adv, "ConvertStringSidToSidW", [C.c_wchar_p, PTR])(sid, C.byref(self.sid)))
        try:
            for station, access in ((True, 0x123), (False, 0xC7)):
                handle = self.open(station)
                self.granted.append((handle, station))
                self.change(handle, access, 1)  # GRANT_ACCESS; no screen-reading/hook/switch rights.
        except BaseException:
            try:
                self.close()
            except OSError:
                pass  # первичная ошибка важнее ошибки отзыва прав
            raise

    def open(self, station):
        """Свежий дескриптор текущей станции/рабочего стола с правом менять DACL (у унаследованного процессом он не гарантирован)."""
        if station:
            current = function(self.user, "GetProcessWindowStation", [], PTR)()
        else:
            tid = function(self.kernel, "GetCurrentThreadId", [])()
            current = function(self.user, "GetThreadDesktop", [U32], PTR)(tid)
        checked(current)
        info = function(self.user, "GetUserObjectInformationW", [PTR, C.c_int, PTR, U32, PTR])
        size = U32()
        info(current, 2, None, 0, C.byref(size))  # UOI_NAME: первый вызов сообщает размер в байтах
        checked(size.value)
        name = C.create_unicode_buffer(size.value // 2 + 1)
        checked(info(current, 2, name, size.value, C.byref(size)))
        if station:
            opened = function(self.user, "OpenWindowStationW", [C.c_wchar_p, U32, U32], PTR)(name.value, 0, self.EDIT_DACL)
        else:
            opened = function(self.user, "OpenDesktopW", [C.c_wchar_p, U32, U32, U32], PTR)(name.value, 0, 0, self.EDIT_DACL)
        checked(opened)
        return opened

    def change(self, handle, access, mode):
        old_acl, descriptor, new_acl = PTR(), PTR(), PTR()
        status(function(self.adv, "GetSecurityInfo", [PTR, U32, U32, PTR, PTR, PTR, PTR, PTR])(
            handle, 7, 4, None, None, C.byref(old_acl), None, C.byref(descriptor)))
        try:
            if not old_acl:  # NULL DACL = доступ у всех; SetEntriesInAcl сузил бы его до одной записи
                raise OSError("У объекта USER нет DACL; права не изменены, чтобы не закрыть доступ владельцу.")
            entry = ExplicitAccess(access, mode, 0, Trustee(None, 0, 0, 1, self.sid))
            status(function(self.adv, "SetEntriesInAclW", [U32, PTR, PTR, PTR])(
                1, C.byref(entry), old_acl, C.byref(new_acl)))
            status(function(self.adv, "SetSecurityInfo", [PTR, U32, U32, PTR, PTR, PTR, PTR])(
                handle, 7, 4, None, None, new_acl, None))
        finally:
            free = function(self.kernel, "LocalFree", [PTR], PTR)
            if new_acl:
                free(new_acl)
            free(descriptor)

    def close(self):
        errors = []
        for handle, station in reversed(self.granted):
            try:
                self.change(handle, 0, 4)  # REVOKE_ACCESS: never restore a stale whole-desktop DACL.
            except OSError as exc:
                errors.append(exc)
            finally:
                function(self.user, "CloseWindowStation" if station else "CloseDesktop", [PTR])(handle)
        self.granted = []
        if self.sid:
            function(self.kernel, "LocalFree", [PTR], PTR)(self.sid)
            self.sid = None
        if errors:
            raise errors[0]


class Child:
    def __init__(self, username, password, command, cwd, env, sid):
        self.kernel, adv = dll("kernel32"), dll("advapi32")
        self.job, self.info, self.desktop = None, ProcessInfo(), None
        self.close_handle = function(self.kernel, "CloseHandle", [PTR])
        try:
            self.desktop = DesktopAccess(sid)
            self.job = function(self.kernel, "CreateJobObjectW", [PTR, C.c_wchar_p], PTR)(None, None)
            checked(self.job)
            limits = ExtendedLimits(basic=BasicLimits(flags=0x2000 | 0x200 | 8, processes=512), jobMemory=8 << 30)
            checked(function(self.kernel, "SetInformationJobObject", [PTR, U32, PTR, U32])(
                self.job, 9, C.byref(limits), C.sizeof(limits)))
            ui = U32(0xFF)
            checked(function(self.kernel, "SetInformationJobObject", [PTR, U32, PTR, U32])(
                self.job, 4, C.byref(ui), C.sizeof(ui)))
            startup = Startup(cb=C.sizeof(Startup), title="AI Sandbox - " + username)
            block = C.create_unicode_buffer(environment_block(env))
            cmdline = C.create_unicode_buffer(command_line(command))
            create = function(adv, "CreateProcessWithLogonW", [C.c_wchar_p, C.c_wchar_p, C.c_wchar_p, U32,
                              C.c_wchar_p, PTR, U32, PTR, C.c_wchar_p, PTR, PTR])
            if not create(username, ".", password, 1, command[0], cmdline, 0x400 | 0x10 | 4, block,
                          str(cwd), C.byref(startup), C.byref(self.info)):  # unicode, new console, suspended
                raise logon_error(C.get_last_error())
            checked(function(self.kernel, "AssignProcessToJobObject", [PTR, PTR])(self.job, self.info.process))
        except BaseException:
            if self.info.process:
                function(self.kernel, "TerminateProcess", [PTR, U32])(self.info.process, 126)
            self.close()
            raise

    def resume(self):
        if function(self.kernel, "ResumeThread", [PTR])(self.info.thread) == 0xFFFFFFFF:
            raise C.WinError(C.get_last_error())

    def wait(self, timeout=None):
        import time
        start = time.monotonic()
        wait = function(self.kernel, "WaitForSingleObject", [PTR, U32])
        while True:
            result = wait(self.info.process, 250)
            if result == 0:
                code = U32()
                checked(function(self.kernel, "GetExitCodeProcess", [PTR, PTR])(self.info.process, C.byref(code)))
                return code.value
            if result != 258:
                raise C.WinError(C.get_last_error())
            if timeout is not None and time.monotonic() - start > timeout:
                raise TimeoutError("native child selftest timed out")

    def close(self):
        if self.job:
            self.close_handle(self.job)  # KILL_ON_JOB_CLOSE includes descendants; no process enumeration.
            self.job = None
        for name in ("thread", "process"):
            value = getattr(self.info, name)
            if value:
                self.close_handle(value)
                setattr(self.info, name, None)
        if self.desktop is not None:
            desktop, self.desktop = self.desktop, None
            desktop.close()


class Lock:
    def __init__(self, username):
        self.kernel = dll("kernel32")
        C.set_last_error(0)
        self.handle = function(self.kernel, "CreateMutexW", [PTR, U32, C.c_wchar_p], PTR)(
            None, 1, "Global\\AISandboxNative-" + username.lower())
        checked(self.handle)
        if C.get_last_error() == 183:
            function(self.kernel, "CloseHandle", [PTR])(self.handle)
            self.handle = None
            raise OSError("another native-user session is active")

    def close(self):
        if self.handle:
            function(self.kernel, "ReleaseMutex", [PTR])(self.handle)
            function(self.kernel, "CloseHandle", [PTR])(self.handle)
            self.handle = None
