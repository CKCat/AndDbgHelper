import base64
import binascii
import os
import platform
import subprocess
import threading
import time

import ida_bytes
import ida_dbg
import ida_ida
import ida_kernwin
import ida_segment
import idaapi
import idautils
import idc
from loguru import logger
from PyQt5.QtWidgets import QApplication

# logger = logging.getLogger("AndDbgHelper")


class MenuContext(idaapi.action_handler_t):
    @classmethod
    def get_name(self):
        return self.__name__

    @classmethod
    def get_label(self):
        return self.label

    @classmethod
    def register(self, plugin, label, shortcut=None):
        self.plugin = plugin
        self.label = label
        instance = self()
        if shortcut is None:
            return idaapi.register_action(
                idaapi.action_desc_t(
                    self.get_name(),  # Name. Acts as an ID. Must be unique.
                    instance.get_label(),  # Label. That's what users see.
                    instance,  # Handler. Called when activated, and for updating
                )
            )
        else:
            return idaapi.register_action(
                idaapi.action_desc_t(
                    self.get_name(),  # Name. Acts as an ID. Must be unique.
                    instance.get_label(),  # Label. That's what users see.
                    instance,  # Handler. Called when activated, and for updating
                    shortcut,  # Optional shortcut
                )
            )

    @classmethod
    def unregister(self):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        idaapi.unregister_action(self.get_name())

    @classmethod
    def activate(self, ctx):
        # dummy method
        return 1

    @classmethod
    def update(self, ctx):
        try:
            if ctx.widget_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_FORM
            else:
                return idaapi.AST_DISABLE_FOR_FORM
        except Exception:
            # Add exception for main menu on >= IDA 7.0
            return idaapi.AST_ENABLE_ALWAYS


class JumpToHexView(MenuContext):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        for i in range(1, 10):
            title = "Hex View-%d" % i
            widget = ida_kernwin.find_widget(title)
            if widget is not None:
                ida_kernwin.activate_widget(widget, True)
                ida_kernwin.jumpto(ea)
                return 1
        idaapi.warning("No Hex View Found")
        return 1


class RVAJumpForm(idaapi.Form):
    def __init__(self, module_address):
        template = r"""STARTITEM 0
BUTTON YES* Jump
Jump without rebase the idb.

                {FormChangeCb}
                <module address:{module_address}>
                <offset address:{offset_address}>
                """
        super(RVAJumpForm, self).__init__(
            template,
            {
                "FormChangeCb": self.FormChangeCb(self.OnFormChange),
                "module_address": self.NumericInput(
                    value=module_address, swidth=40, tp=self.FT_HEX
                ),
                "offset_address": self.NumericInput(
                    value=0, swidth=40, tp=self.FT_HEX
                ),
            },
        )
        self.Compile()

    def OnFormChange(self, fid):
        return 1


class RVAJumpMenu(MenuContext):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        for mod in idautils.Modules():
            if mod.base <= ea <= (mod.base + mod.size):
                form = RVAJumpForm(mod.base)
                if form.Execute() == 1:
                    base_addr = form.module_address.value
                    offset = form.offset_address.value
                    ida_kernwin.jumpto(base_addr + offset)
                    form.Free()
                    return 1
                form.Free()
        return 1


def copy2clipboard(text):
    # 复制到剪切板
    clipboard = QApplication.clipboard()
    clipboard.setText(text)
    clipboard.dataChanged.connect(lambda: print(f"已复制:{text}"))


class RVAOffsetMenu(MenuContext):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        for mod in idautils.Modules():
            if mod.base <= ea <= (mod.base + mod.size):
                copy2clipboard(hex(ea - mod.base))
        return 1


class CopyWord(MenuContext):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        copy2clipboard(hex(ida_bytes.get_word(ea)))
        return 1


class CopyDWord(MenuContext):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        copy2clipboard(hex(ida_bytes.get_dword(ea)))
        return 1


class CopyQWord(MenuContext):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        copy2clipboard(hex(ida_bytes.get_qword(ea)))
        return 1


class DumpMemoryForm(idaapi.Form):
    def __init__(self, module_address):
        template = r"""STARTITEM 0
BUTTON YES* Dump
dump memory to file

                {FormChangeCb}
                <start address:{start_address}>
                <end   address:{end_address}>
                <dump     size:{dump_size}>
                """
        super(DumpMemoryForm, self).__init__(
            template,
            {
                "FormChangeCb": self.FormChangeCb(self.OnFormChange),
                "start_address": self.NumericInput(
                    value=module_address, tp=self.FT_HEX, swidth=40
                ),
                "end_address": self.NumericInput(
                    value=0, tp=self.FT_HEX, swidth=40
                ),
                "dump_size": self.NumericInput(
                    value=0, tp=self.FT_HEX, swidth=40
                ),
            },
        )
        self.Compile()

    def OnFormChange(self, fid):
        return 1


class DumpMemu(MenuContext):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        form = DumpMemoryForm(ea)
        if form.Execute() == 1:
            file_path = ida_kernwin.ask_file(
                True, "*.dump", "please select dump file to save"
            )
            if not file_path:
                ida_kernwin.warning("dump file path is empty")
                form.Free()
                return 1
            end_address = form.end_address.value
            dump_size = form.dump_size.value
            if dump_size <= 0 and end_address <= 0:
                ida_kernwin.warning("size is empty")
                form.Free()
                return 1
            start_address = form.start_address.value
            if end_address > 0 and end_address > start_address:
                bytes_data = idc.get_bytes(
                    start_address,
                    end_address - start_address,
                    idaapi.is_debugger_on(),
                )
                if bytes_data:
                    with open(file_path, "wb") as f:
                        f.write(bytes_data)
                    ida_kernwin.msg("dump success")
                else:
                    ida_kernwin.warning("dump failed")
            elif dump_size > 0:
                bytes_data = idc.get_bytes(
                    start_address, dump_size, idaapi.is_debugger_on()
                )
                if bytes_data:
                    with open(file_path, "wb") as f:
                        f.write(bytes_data)
                    ida_kernwin.msg("dump success")
                else:
                    ida_kernwin.warning("dump failed")
        form.Free()
        return 1


class WriteMemoryForm(idaapi.Form):
    def __init__(self, target_address):
        template = r"""STARTITEM 0
BUTTON YES* Write
Write to Memory

{FormChangeCb}
<Target address : {target_address}>
<Write Hex Data:{hex_data}><Write Base64 Data:{base64_data}><Write ASCII Data:{ascii_data}>{data_type}>
<Input data: {input_data} >
"""
        super(WriteMemoryForm, self).__init__(
            template,
            {
                "FormChangeCb": self.FormChangeCb(self.OnFormChange),
                "target_address": self.StringInput(
                    value="0x{:x}".format(target_address)
                ),
                "data_type": idaapi.Form.RadGroupControl(
                    {"hex_data", "base64_data", "ascii_data"}, value=0
                ),
                "input_data": idaapi.Form.MultiLineTextControl(
                    text="", swidth=60
                ),
            },
        )
        self.Compile()

    def OnFormChange(self, fid):
        # if fid == self.data_type.id:
        #     print("data type changed:", self.GetControlValue(self.data_type))
        return 1


class WriteMemoryData(MenuContext):
    stop_words =  [",", "0x", "0X", "{", "}", "H", "h", "[", "]", " ", "\n", "\r" ";"]  # fmt: skip

    def activate(self, ctx):
        ea = idc.get_screen_ea()
        form = WriteMemoryForm(ea)
        if form.Execute() == 1:
            data_type = form.data_type.value
            string_data = form.input_data.value
            target_address = int(form.target_address.value, 16)
            if string_data is None or len(string_data) <= 0:
                ida_kernwin.warning("input data is empty")
                form.Free()
                return 1
            if target_address <= 0:
                ida_kernwin.warning("target address is empty")
                form.Free()
                return 1
            string_data = string_data.strip()

            for ch in WriteMemoryData.stop_words:
                string_data = string_data.replace(ch, "")

            if data_type == 0:
                if len(string_data) % 2 != 0:
                    ida_kernwin.warning("hex data length must be even")
                    form.Free()
                    return 1
                else:
                    hex_data = string_data
                    write_addr = target_address
                    try:
                        hex_data = bytearray(binascii.a2b_hex(hex_data))
                        for i in range(len(hex_data)):
                            idaapi.patch_byte(write_addr + i, hex_data[i])
                        print("write success")
                    except Exception as e:
                        logger.warning(e)
                        ida_kernwin.warning("write failed")

            elif data_type == 1:
                try:
                    base64_data = bytearray(base64.b64decode(string_data))
                    write_addr = target_address
                    for i in range(len(base64_data)):
                        idaapi.patch_byte(write_addr + i, base64_data[i])
                    print("write success")
                except Exception as e:
                    logger.warning(e)
                    ida_kernwin.warning("write failed")
            elif data_type == 2:
                try:
                    ascii_data = bytearray(string_data.encode("utf-8"))
                    write_addr = target_address
                    for i in range(len(ascii_data)):
                        idaapi.patch_byte(write_addr + i, ascii_data[i])
                    print("write success")
                except Exception as e:
                    logger.warning(e)
                    ida_kernwin.warning("write failed")
        return 1


class CopyMemoryForm(idaapi.Form):
    stop_words = [",", "0x", "0X", "{", "}", "H", "h", "[", "]", " ", "\n", "\r" ";"]  # fmt: skip

    def __init__(self, target_address):
        template = r"""STARTITEM 0
BUTTON YES* OK
Copy From Memory

{FormChangeCb}
<Target address : {target_address}>
<Data    length :{data_length}>
<Copy Hex Data:{hex_data}><Copy Base64 Data:{base64_data}><Copy ASCII Data:{string_data}>{data_type}>
<Out data: {input_data} >
<Copy Data:{copy_data}>
"""
        super(CopyMemoryForm, self).__init__(
            template,
            {
                "FormChangeCb": self.FormChangeCb(self.OnFormChange),
                "target_address": self.StringInput(
                    value="0x{:x}".format(target_address)
                ),
                "data_length": self.StringInput(value="0xf"),
                "data_type": idaapi.Form.RadGroupControl(
                    {"hex_data", "base64_data", "string_data"}, value=0
                ),
                "input_data": idaapi.Form.StringInput(value="123", swidth=50),
                "copy_data": idaapi.Form.ButtonInput(
                    handler=self.OnCopyButtonClick, swidth=60
                ),
            },
        )
        self.Compile()

    def OnCopyButtonClick(self, code=0):
        data_type_value = self.GetControlValue(self.data_type)
        dump_address = self.get_copy_address()
        length = self.get_data_length()
        if length <= 0 or dump_address <= 0:
            ida_kernwin.warning("address is invalid")
            return
        if not self.is_address_readable(
            dump_address
        ) or not self.is_address_readable(dump_address + length):
            ida_kernwin.warning(
                "address is not readable",
                hex(dump_address),
                "-",
                hex(dump_address + length),
            )
            return
        if data_type_value == 0:
            read_bytes = idc.get_bytes(
                dump_address, length, ida_dbg.is_debugger_on()
            )
            hex_str = str(binascii.hexlify(read_bytes).decode("utf-8"))
            self.SetControlValue(self.input_data, hex_str)
            copy2clipboard(hex_str)
            return
        elif data_type_value == 1:
            read_bytes = idc.get_bytes(
                dump_address, length, ida_dbg.is_debugger_on()
            )
            base64_str = base64.b64encode(read_bytes).decode("utf-8")
            self.SetControlValue(self.input_data, base64_str)
            copy2clipboard(base64_str)
        elif data_type_value == 2:
            self.EnableField(self.data_length, False)
            temp_address = dump_address
            read_bytes = bytearray()
            while True:
                read_byte = idc.get_bytes(
                    temp_address, 1, ida_dbg.is_debugger_on()
                )
                if read_byte == b"\x00":
                    break
                temp_address += 1
                read_bytes += read_byte
            ascii_str = read_bytes.decode("utf-8")
            self.SetControlValue(self.input_data, ascii_str)
            copy2clipboard(ascii_str)

    def get_data_length(self):
        length = self.GetControlValue(self.data_length)
        length = length.strip()
        for ch in CopyMemoryForm.stop_words:
            length = length.replace(ch, "")
        try:
            length = int(length, 16)
            if length <= 0:
                return 16
            if length > 1000:
                return 1000
            return length
        except Exception as e:
            logger.warning(e)

        return 16

    def get_copy_address(self):
        address = self.GetControlValue(self.target_address)
        address = address.strip()
        try:
            for ch in CopyMemoryForm.stop_words:
                address = address.replace(ch, "")
            address = int(address, 16)
            if address <= 0:
                return 0
            return address
        except Exception as e:
            logger.warning(e)
        return 0

    def is_address_readable(self, address):
        # 获取地址所在的段
        seg = ida_segment.getseg(address)
        if seg is None:
            return False
        if seg.perm & ida_segment.SEGPERM_READ:
            return True
        else:
            return False

    def OnFormChange(self, fid):
        self._is_processing = True
        if fid == self.data_type.id:
            if self.GetControlValue(self.data_type) == 2:
                self.EnableField(self.data_length, False)
            else:
                self.EnableField(self.data_length, True)

        return 1


class CopyMemoryData(MenuContext):
    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        if ea == idaapi.BADADDR:
            ida_kernwin.warning("address is invalid")
            return 1
        form = CopyMemoryForm(ea)
        if form.Execute() == 1:
            form.Execute()
            form.Free()
        return 1


class DebuggerUiHook(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        if not ida_dbg.is_debugger_on():
            return

        if idaapi.IDA_SDK_VERSION >= 900:
            dump_type = idaapi.BWN_HEXVIEW
        else:
            dump_type = idaapi.BWN_DUMP

        if ida_kernwin.get_widget_type(form) == idaapi.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(
                form, popup, JumpToHexView.get_name()
            )
            ida_kernwin.attach_action_to_popup(
                form, popup, RVAJumpMenu.get_name()
            )
            ida_kernwin.attach_action_to_popup(
                form, popup, RVAOffsetMenu.get_name()
            )
        elif ida_kernwin.get_widget_type(form) == dump_type:
            ida_kernwin.attach_action_to_popup(form, popup, DumpMemu.get_name())
            ida_kernwin.attach_action_to_popup(
                form, popup, WriteMemoryData.get_name()
            )
            ida_kernwin.attach_action_to_popup(
                form, popup, CopyMemoryData.get_name(), "Copy/"
            )
            ida_kernwin.attach_action_to_popup(
                form, popup, CopyWord.get_name(), "Copy/"
            )
            ida_kernwin.attach_action_to_popup(
                form, popup, CopyDWord.get_name(), "Copy/"
            )
            ida_kernwin.attach_action_to_popup(
                form, popup, CopyQWord.get_name(), "Copy/"
            )


class JdbRunner:
    def __init__(self, jdb_debug_port=8700):
        self.jdb_debug_port = jdb_debug_port
        self.process = None
        self.thread = None
        self.is_running = False

    def start(self):
        def run_jdb():
            """运行 JDB"""
            cmd = f"jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port={self.jdb_debug_port}"
            logger.debug(f"正在启动 JDB: {cmd}")
            try:
                self.process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                )
                self.is_running = True

                # 持续读取输出，防止缓冲区填满
                while self.is_running:
                    output = self.process.stdout.readline()
                    if output:
                        logger.debug(f"JDB 输出: {output.strip()}")
                    if self.process.poll() is not None:
                        break
            except Exception as e:
                logger.error(f"JDB 运行时发生错误: {str(e)}")
            finally:
                self.is_running = False

        self.thread = threading.Thread(target=run_jdb)
        self.thread.start()

    def stop(self):
        """停止 JDB"""
        self.is_running = False
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
        if self.thread:
            self.thread.join(timeout=5)


class Device:
    """设备管理类"""

    device_serial = ""
    grep = "grep"
    if platform.system() == "Windows":
        grep = "findstr"

    @staticmethod
    def list_devices():
        """获取设备列表"""
        output = Device.run_adb_command("adb devices -l")
        if not output:
            logger.debug("No devices found")
            return {}

        output = output.replace("\r", "").split("\n")[1:]
        devices = set()
        for device in output:
            device = device.strip()
            if device and "device" in device:  # 只处理已连接的设备
                devices.add(tuple(device.split()))

        device_info = {}
        for d in devices:
            device_id = d[0]
            props = {t.split(":")[0]: t.split(":")[1] for t in d[2:]}
            props["version"] = Device.get_android_version(device_id)
            device_info[device_id] = props

        if device_info:
            Device.device_serial = next(iter(device_info))

        Device.devices = device_info
        return device_info

    @staticmethod
    def run_adb_command(command: str | list[str], max_retries: int = 1) -> str:
        """执行 adb 命令

        Args:
            command: 要执行的命令
            max_retries: 最大重试次数

        Returns:
            str: 命令输出
        """

        while bool(max_retries):  # 0 则为 False
            try:
                max_retries -= 1
                result = subprocess.run(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=1,
                )

                if result.returncode == 0:
                    logger.debug(
                        "stdout: {}",
                        result.stdout.decode("utf-8", errors="ignore").strip(),
                    )
                    return result.stdout.decode(
                        "utf-8", errors="ignore"
                    ).strip()

                error = result.stderr.decode("utf-8", errors="ignore").strip()
                logger.debug(f"[-] ADB Error {command} : {error}")
                if bool(max_retries):
                    time.sleep(1)

            except subprocess.TimeoutExpired:
                logger.debug(f"[-] Command timeout {command}")
                if bool(max_retries):
                    time.sleep(1)

            except Exception as e:
                logger.debug(f"[-] Command failed {command} : {str(e)}")
                if bool(max_retries):
                    time.sleep(1)

        return ""

    @staticmethod
    def push_android_server(android_server_path: str, remote_path: str) -> bool:
        """推送 android_server 到Android设备"""
        result = Device.run_adb_command(
            f'adb -s {Device.device_serial} push "{android_server_path}" {remote_path}'
        )
        return bool(result)

    @staticmethod
    def run_android_server(remote_path: str, port: int = 23946) -> bool:
        """运行 android_server"""
        android_server = remote_path.split("/")[-1]

        # 设置执行权限
        Device.run_adb_command(
            f"adb -s {Device.device_serial} shell chmod +x {remote_path}"
        )

        # 杀死已运行的服务
        kill_cmd = [
            "adb",
            "-s",
            Device.device_serial,
            "shell",
            f"su -c killall {android_server} ",
        ]
        try:
            Device.run_adb_command(kill_cmd)
        except Exception as e:
            logger.debug(f"[-] Kill android_server failed: {str(e)}")

        # 启动服务器
        run_android_server = f"{remote_path} -p {port} > /dev/null 2>&1 &"
        execute_cmd = [
            "adb",
            "-s",
            Device.device_serial,
            "shell",
            f"su -c {run_android_server}",
        ]
        try:
            Device.run_adb_command(execute_cmd)
        except Exception as e:
            logger.debug(f"[-] Kill android_server failed: {str(e)}")
        return True

    @staticmethod
    def start_and_wait_for_app(package_name: str, max_attempts: int = 3) -> int:
        """启动应用并获取其 PID"""
        while bool(max_attempts):
            max_attempts -= 1
            Device.run_adb_command(
                f"adb -s {Device.device_serial} shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1"
            )
            pid = Device.run_adb_command(
                f"adb -s {Device.device_serial} shell pidof {package_name}"
            )
            if pid:
                return int(pid)
            time.sleep(1)
        return 0

    @staticmethod
    def forward_tcp(port: int = 23946) -> bool:
        """设置 TCP 端口转发"""
        result = Device.run_adb_command(
            f"adb -s {Device.device_serial} forward tcp:{port} tcp:{port}"
        )
        return bool(result)

    @staticmethod
    def forward_jdwp(pid: int, jdb_debug_port: int = 8700) -> bool:
        """设置 JDWP 端口转发"""
        result = Device.run_adb_command(
            f"adb -s {Device.device_serial} forward tcp:{jdb_debug_port} jdwp:{pid}"
        )
        return bool(result)

    @staticmethod
    def jdb_connect(jdb_debug_port: int = 8700, timeout: int = 3) -> JdbRunner:
        """连接 JDB"""
        jdb_runner = JdbRunner(jdb_debug_port)
        jdb_runner.start()

    @staticmethod
    def set_application_to_debug_mode(package_name: str) -> bool:
        """设置应用调试模式"""
        result = Device.run_adb_command(
            f"adb -s {Device.device_serial} shell am set-debug-app -w {package_name}"
        )
        return bool(result)

    @staticmethod
    def remove_application_from_debug_mode():
        """移除应用调试模式"""
        Device.run_adb_command(
            f"adb -s {Device.device_serial} shell am clear-debug-app"
        )

    @staticmethod
    def get_android_version(device_serial: str) -> str:
        """获取设备 Android 版本"""
        output = Device.run_adb_command(
            f"adb -s {device_serial} shell getprop ro.build.version.release"
        )
        return output

    @staticmethod
    def get_android_server_port(android_server: str) -> int:
        """获取正在运行的 android_server 的端口号"""
        netstat = f"netstat -tulnp | {Device.grep} {android_server}"
        command = f"adb -s {Device.device_serial} shell su -c {netstat}"
        logger.debug(command)
        result = Device.run_adb_command(command)
        if result:
            # 提取端口号
            port = result.split()[3].split(":")[-1]
            return int(port)
        else:
            logger.debug(f"[-] {android_server} 未运行")
            return 0

    @staticmethod
    def is_port_in_use(port: int) -> bool:
        """检查设备上的端口是否被占用"""
        netstat = f"netstat -tulnp | {Device.grep} :{port}"
        command = f"adb -s {Device.device_serial} shell su -c {netstat}"
        result = Device.run_adb_command(command)
        return bool(result)

    @staticmethod
    def check_adb_available() -> bool:
        """检查 ADB 是否可用"""
        result = Device.run_adb_command("adb version")
        return bool(result)

    @staticmethod
    def check_server_status(name: str) -> bool:
        """检查进程状态"""
        result = Device.run_adb_command(
            f"adb -s {Device.device_serial} shell ps -a | {Device.grep} {name}"
        )
        return bool(result)


class AndDbgHelper(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = (
        "Android JNI and SO Debugger Plugin with auto debugging and dumping"
    )
    help = "Automatically debug, set breakpoints, and dump SO memory."
    wanted_name = "AndDbgHelper"
    wanted_hotkey = "Alt-F9"
    version = "0.1"

    def __init__(self):
        super().__init__()
        # 基本配置
        self.package_name = ""
        self.so_name = ""
        self.ida_path = ""
        self.android_server_path = ""
        self.android_server = ""
        self.remote_path = "/data/local/tmp/"
        self.remote_host = "127.0.0.1"
        self.remote_port = 23946  # 默认端口
        self.jdb_debug_port = 8700
        self.devices = {}
        self.is_init = False

        # 断点配置
        self.set_jni_onload_bpt = True
        self.set_init_proc_bpt = True
        self.set_init_array_bpt = True

        # 调试配置
        self.max_retries = 3
        self.adb_timeout = 10
        self.dump_chunk_size = 0x10000

    def init(self):
        """初始化插件"""
        try:
            DumpMemu.register(self, "Dump Data")
            WriteMemoryData.register(self, "Write Data")
            CopyMemoryData.register(self, "Copy Data")
            JumpToHexView.register(self, "Sync HexView")
            RVAJumpMenu.register(self, "RVA Jump")
            RVAOffsetMenu.register(self, "RVA Offset")
            CopyWord.register(self, "Copy Word")
            CopyDWord.register(self, "Copy DWord")
            CopyQWord.register(self, "Copy QWord")
        except:
            pass
        self.popup_ui_hook = DebuggerUiHook()
        self.popup_ui_hook.hook()
        logger.info(
            f"[+] AndDbgHelper {self.version} Plugin initialized successfully"
        )
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        try:
            if not self.is_init:
                # 验证 IDA 路径
                self.ida_path = idc.idadir()
                # 选择合适的 android_server
                self.android_server = (
                    "android_server"
                    if not ida_ida.inf_is_32bit_exactly()
                    else "android_server32"
                )
                self.android_server_path = os.path.join(
                    self.ida_path, "dbgsrv", self.android_server
                )
                self.remote_path = os.path.join(
                    self.remote_path, self.android_server
                )
                if not os.path.exists(self.android_server_path):
                    raise RuntimeError(
                        f"Android server not found: {self.android_server_path}"
                    )
                logger.debug(f"[+] Using {self.android_server}")

                self.so_name = idaapi.get_root_filename()
                # 获取设备列表
                self.devices = Device.list_devices()
                if not self.devices:
                    idaapi.msg("[-] No devices found. Exiting.")
                    return
                logger.debug(f"[+] Found {self.devices} devices.")
                self.is_init = True

            self.show_input_dialog()
            if not self.package_name:
                logger.error("[-] Package name not specified. Exiting.")
                return
            self.start_debugging()
        except Exception as e:
            logger.error(f"[-] Error: {str(e)}")

    def term(self):
        if self.popup_ui_hook is not None:
            self.popup_ui_hook.unhook()
            self.popup_ui_hook = None
        Device.remove_application_from_debug_mode()
        logger.debug("[+] Android SO Debugger Plugin unloaded.")

    def show_input_dialog(self):
        """显示用户输入配置的对话框"""
        device_items = []
        for device_id, info in self.devices.items():
            model = info.get("model", "Unknown")
            version = info.get("version", "Unknown")
            device_items.append(f"{device_id} ({model} Android {version})")

        try:
            form = ida_kernwin.Form(
                """Android SO Debugger Configuration

                <Device:{device_chooser}>
                <Package Name:{package_name}>
                <Remote Server Path:{remote_path}>
                <Remote Server Host:{remote_host}>
                <Remote Server Port:{remote_port}>
                <JDB Debug Port:{jdb_debug_port}>

                <##Basic Breakpoints##
                Set breakpoints at jni_onload:{jni_onload}>
                <Set breakpoints at init_proc:{init_proc}>
                <Set breakpoints at init_array:{init_array}>{breakpoint_group}>
                """,
                {
                    "package_name": ida_kernwin.Form.StringInput(swidth=40),
                    "device_chooser": ida_kernwin.Form.DropdownListControl(
                        items=device_items, readonly=True, selval=0
                    ),
                    "remote_path": ida_kernwin.Form.StringInput(swidth=40),
                    "remote_host": ida_kernwin.Form.StringInput(swidth=40),
                    "remote_port": ida_kernwin.Form.NumericInput(
                        swidth=10, tp=ida_kernwin.Form.FT_DEC
                    ),
                    "jdb_debug_port": ida_kernwin.Form.NumericInput(
                        swidth=10, tp=ida_kernwin.Form.FT_DEC
                    ),
                    "breakpoint_group": ida_kernwin.Form.ChkGroupControl(
                        ("jni_onload", "init_proc", "init_array")
                    ),
                },
            )
            form.Compile()

            # 设置默认值
            form.package_name.value = self.package_name
            form.remote_path.value = self.remote_path
            form.remote_host.value = self.remote_host
            form.remote_port.value = self.remote_port
            form.jdb_debug_port.value = self.jdb_debug_port
            # 将多选框状态转换为整数掩码
            breakpoint_mask = 0
            if self.set_jni_onload_bpt:
                breakpoint_mask |= 1 << 0  # 第一个多选框
            if self.set_init_proc_bpt:
                breakpoint_mask |= 1 << 1  # 第二个多选框
            if self.set_init_array_bpt:
                breakpoint_mask |= 1 << 2  # 第三个多选框
            form.breakpoint_group.value = breakpoint_mask

            if form.Execute() == 1:
                # 获取用户输入的值
                self.package_name = form.package_name.value
                self.remote_path = form.remote_path.value
                self.remote_host = form.remote_host.value
                self.remote_port = form.remote_port.value
                self.jdb_debug_port = form.jdb_debug_port.value
                index = form.device_chooser.value
                Device.device_serial = device_items[index].split(" ")[0]

                breakpoint_mask = form.breakpoint_group.value
                self.set_jni_onload_bpt = bool(breakpoint_mask & (1 << 0))
                self.set_init_proc_bpt = bool(breakpoint_mask & (1 << 1))
                self.set_init_array_bpt = bool(breakpoint_mask & (1 << 2))

            form.Free()

        except Exception as e:
            logger.error(f"[-] Error showing input dialog: {str(e)}")

    def start_debugging(self):
        """启动调试，并自动设置断点"""
        logger.debug("Starting Android debugging...")

        try:
            # 拷贝并启动 Android 服务端
            Device.push_android_server(
                self.android_server_path, self.remote_path
            )
            if not Device.run_android_server(
                self.remote_path, self.remote_port
            ):
                logger.error("[-] Failed to start Android server")
                return False

            # 设置端口转发
            Device.forward_tcp(self.remote_port)

            # 设置应用为调试模式
            Device.set_application_to_debug_mode(self.package_name)

            # 启动应用
            pid = Device.start_and_wait_for_app(self.package_name)
            if not pid:
                logger.error(f"[-] Failed to start {self.package_name}")
                return False

            # 设置 JDWP 端口转发
            Device.forward_jdwp(pid, self.jdb_debug_port)

            try:
                # ida_dbg.set_debugger_options(
                #     ida_dbg.DOPT_LIB_BPT | ida_dbg.DOPT_THREAD_BPT
                # )

                # 设置远程调试器
                ida_dbg.set_remote_debugger(
                    self.remote_host, str(self.remote_port)
                )

                # 附加到进程
                ida_dbg.attach_process(pid, 1)

                logger.debug(f"[+] Successfully attached debugger: PID={pid}")

                # 继续执行进程
                ida_dbg.continue_process()
                logger.debug(f"[+] Successfully running {self.package_name}")

                # 等待调试器事件
                ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 1)

            except Exception as e:
                logger.error(f"[-] Failed to attach debugger: {str(e)}")
                return False

            # 连接 JDB
            Device.jdb_connect(self.jdb_debug_port)
            logger.debug("[+] Successfully connected to JDB")

            return True

        except Exception as e:
            logger.error(f"Error during debugging setup: {str(e)}")
            return False

    def set_breakpoint(self, ea):
        """设置断点并增加错误处理"""
        if ida_dbg.add_bpt(ea):
            logger.debug(f"[+] Breakpoint set at 0x{ea:08X}")
        else:
            logger.debug(f"[-] Failed to set breakpoint at 0x{ea:08X}")
            ida_kernwin.warning(f"Failed to set breakpoint at 0x{ea:08X}")

    def find_and_set_breakpoints(self):
        """寻找并设置断点，支持更多类型"""
        # 设置 JNI_OnLoad 断点
        if self.set_jni_onload_bpt:
            jni_onload_addr = idc.get_name_ea_simple("JNI_OnLoad")
            if jni_onload_addr != idc.BADADDR:
                logger.debug(f"[+] Found JNI_OnLoad at 0x{jni_onload_addr:08X}")
                self.set_breakpoint(jni_onload_addr)
            else:
                logger.debug("[-] JNI_OnLoad not found")
        # TODO set_init_proc_bpt 和 set_init_array_bpt


# 注册插件
def PLUGIN_ENTRY():
    return AndDbgHelper()
