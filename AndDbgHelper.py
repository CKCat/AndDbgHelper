import os
import platform
import subprocess
import threading
import time

import ida_dbg
import ida_ida
import ida_kernwin
import idaapi
import idc
from loguru import logger

# logger = logging.getLogger("AndDbgHelper")


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
