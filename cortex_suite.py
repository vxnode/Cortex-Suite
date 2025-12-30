import sys, psutil, platform, subprocess, socket, datetime, threading, time, requests, json, os
from PyQt6 import QtWidgets, QtGui, QtCore
from collections import namedtuple

try:
    import GPUtil
except ImportError:
    class MockGPU:
        name = "GPUtil Not Installed"
        memoryUsed = 0
        memoryTotal = 0
    class GPUtil:
        @staticmethod
        def getGPUs():
            return [MockGPU()]

SETTINGS_FILE = 'cortex_settings.json'
DEFAULT_WALLPAPER_PATH = 'wallpaper.jpg'
DEFAULT_BLUR_RADIUS = 10 
CORNER_RADIUS = 15

ConnectionDetails = namedtuple(
    "ConnectionDetails", 
    ["local_addr", "remote_addr", "status", "pid", "pname", "remote_ip"]
)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org", timeout=3).text
    except:
        return "N/A"

def get_gpu_info():
    gpus = GPUtil.getGPUs()
    if gpus:
        gpu = gpus[0]
        return f"{gpu.name} ({gpu.memoryUsed}/{gpu.memoryTotal} MB)"
    return "No GPU detected"

def get_disk_usage():
    try:
        disk = psutil.disk_usage(os.path.abspath(os.sep))
        return f"{disk.percent}% ({round(disk.used/1e9, 1)}/{round(disk.total/1e9, 1)} GB)"
    except Exception:
        return "N/A"

def get_process_name(pid):
    try:
        return psutil.Process(pid).name()
    except psutil.NoSuchProcess:
        return "N/A (Process terminated)"
    except Exception:
        return "Unknown"

def get_active_connections():
    connections = []
    
    COLOR_LISTENING = QtGui.QColor(255, 255, 0, 150) 
    COLOR_REMOTE = QtGui.QColor(0, 240, 255) 
    
    for conn in psutil.net_connections(kind='inet'):
        
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        
        remote_ip = None
        if conn.raddr:
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}"
            remote_ip = conn.raddr.ip
            color = COLOR_REMOTE
        else:
            raddr = "N/A"
            color = COLOR_LISTENING 

        pname = get_process_name(conn.pid) if conn.pid else "N/A"
        
        details = ConnectionDetails(laddr, raddr, conn.status, conn.pid, pname, remote_ip)
        
        item = QtWidgets.QListWidgetItem()
        item.setText(f"{laddr:<22} -> {raddr:<22} | {conn.status:<10} | PID: {conn.pid:<5} | {pname}")
        item.setData(QtCore.Qt.ItemDataRole.UserRole, details)
        
        item.setForeground(color)
        
        connections.append(item)
        
    return connections

def get_network_interface_stats():
    stats_list = []
    
    addresses = psutil.net_if_addrs()
    io_counters = psutil.net_io_counters(pernic=True)
    stats = psutil.net_if_stats()
    
    for name, addrs in addresses.items():
        mac_addr = "N/A"
        ipv4_addr = "N/A"
        
        for addr in addrs:
            if addr.family == psutil.AF_LINK: 
                mac_addr = addr.address
            elif addr.family == socket.AF_INET: 
                ipv4_addr = addr.address

        interface_stats = stats.get(name)
        status = "Up" if interface_stats and interface_stats.isup else "Down"
        speed_mbps = f"{interface_stats.speed} Mbps" if interface_stats and interface_stats.speed > 0 else "N/A"
        
        io = io_counters.get(name)
        bytes_sent = f"{round(io.bytes_sent/1024/1024, 1)} MB" if io else "N/A"
        bytes_recv = f"{round(io.bytes_recv/1024/1024, 1)} MB" if io else "N/A"

        stats_list.append({
            'name': name,
            'status': status,
            'ipv4': ipv4_addr,
            'mac': mac_addr,
            'speed': speed_mbps,
            'sent': bytes_sent,
            'recv': bytes_recv,
        })
    return stats_list


def _fetch_geolocation_data(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query", timeout=5)
        response.raise_for_status() 
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        return {"status": "fail", "message": f"Network Error: {e}"}
    except Exception as e:
        return {"status": "fail", "message": f"An unknown error occurred: {e}"}

class SettingsManager:
    def __init__(self, file_path):
        self.file_path = file_path
        self.settings = self.load_settings()

    def _default_settings(self):
        return {
            'wallpaper_path': DEFAULT_WALLPAPER_PATH,
            'blur_radius': DEFAULT_BLUR_RADIUS,
            'window_geometry': "100,100,1400,850",
            'tasks': [],
            'autostart': False,
            'apps': [] 
        }

    def load_settings(self):
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, 'r') as f:
                    return {**self._default_settings(), **json.load(f)}
            except:
                pass
        return self._default_settings()

    def save_settings(self):
        try:
            with open(self.file_path, 'w') as f:
                json.dump(self.settings, f, indent=4)
        except:
            print("Failed to save settings")


class AppsTab(QtWidgets.QWidget):
    
    def __init__(self, settings_manager):
        super().__init__()
        self.settings_manager = settings_manager
        self.apps = self.settings_manager.settings.get('apps', [])
        self.init_ui()
        self.refresh_app_list()

    def init_ui(self):
        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        add_app_frame = QtWidgets.QFrame()
        add_app_frame.setStyleSheet("background: rgba(0,0,0,100); border-radius: 10px; padding: 10px;")
        add_app_layout = QtWidgets.QHBoxLayout(add_app_frame)
        
        self.app_name_input = QtWidgets.QLineEdit()
        self.app_name_input.setPlaceholderText("Enter App Name")
        add_app_layout.addWidget(self.app_name_input)
        
        self.btn_add_app = QtWidgets.QPushButton("Add App Shortcut")
        self.btn_add_app.clicked.connect(self.add_app_shortcut)
        add_app_layout.addWidget(self.btn_add_app)
        
        main_layout.addWidget(add_app_frame)
        

        app_list_label = QtWidgets.QLabel("Registered Applications")
        app_list_label.setStyleSheet("font-size: 18px; font-weight: bold; margin-top: 15px; padding: 5px;")
        main_layout.addWidget(app_list_label)


        scroll_area = QtWidgets.QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: 1px solid #00f0ff; border-radius: 5px; background: rgba(0, 0, 0, 150); }")

        self.app_buttons_container = QtWidgets.QWidget()
        self.app_buttons_container.setStyleSheet("background: transparent;") 
        

        self.app_buttons_layout = QtWidgets.QVBoxLayout(self.app_buttons_container)
        self.app_buttons_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop | QtCore.Qt.AlignmentFlag.AlignLeft)
        
        scroll_area.setWidget(self.app_buttons_container)
        main_layout.addWidget(scroll_area, 1) 
        
        management_layout = QtWidgets.QHBoxLayout()
        
        self.btn_remove = QtWidgets.QPushButton("Remove Selected") 
        self.btn_remove.setStyleSheet("background: #ff8800; color: white;")
        self.btn_remove.setEnabled(False) 
        self.btn_remove.clicked.connect(self.remove_selected_app)
        
        management_layout.addWidget(self.btn_remove)
        management_layout.addStretch(1)

        main_layout.addLayout(management_layout)
        
        self.selected_app_data = None 

    def add_app_shortcut(self):
        app_name = self.app_name_input.text().strip()
        if not app_name:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please enter a name for the application.", QtWidgets.QMessageBox.StandardButton.Ok)
            return

        app_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, 
            "Select Application Executable", 
            "", 
            "Executables (*.exe *.app *.sh);;All Files (*)"
        )

        if app_path:
            if any(app['path'] == app_path for app in self.apps):
                QtWidgets.QMessageBox.information(self, "App Exists", f"The application at {app_path} is already registered.", QtWidgets.QMessageBox.StandardButton.Ok)
                return
                    
            self.apps.append({'name': app_name, 'path': app_path})
            self._save_apps()
            self.refresh_app_list()
            self.app_name_input.clear()
            QtWidgets.QMessageBox.information(self, "Success", f"'{app_name}' shortcut added.", QtWidgets.QMessageBox.StandardButton.Ok)

    def create_app_button(self, app_data):
        
        app_name = app_data['name']
        app_path = app_data['path']
        
        app_button = QtWidgets.QPushButton()
        app_button.setText(f"🚀 {app_name}")
        app_button.setToolTip(f"Path: {app_path}")
        
        app_button.setStyleSheet("""
            QPushButton {
                background: rgba(0, 240, 255, 150);
                color: #000;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
                text-align: left;
                margin-bottom: 5px;
            }
            QPushButton:hover {
                background: #fff;
            }
            QPushButton:checked { 
                background: #ff8800; 
                color: white;
            }
        """)
        app_button.setCheckable(True) 
        
        app_button.clicked.connect(lambda checked, data=app_data: self.handle_app_button_click(data, checked))
        
        return app_button

    def handle_app_button_click(self, app_data, checked):
        sender_button = self.sender()
        
        if checked:
            self.selected_app_data = app_data
            self.btn_remove.setEnabled(True)
            
            for i in range(self.app_buttons_layout.count()):
                widget = self.app_buttons_layout.itemAt(i).widget()
                if widget and widget != sender_button and hasattr(widget, 'setChecked'):
                    widget.setChecked(False)
        else:
            self.launch_app(app_data)
            
            sender_button.setChecked(False)
            self.selected_app_data = None
            self.btn_remove.setEnabled(False)


    def launch_app(self, app_data):
        app_path = app_data['path']
        try:
            subprocess.Popen([app_path], shell=False) 
            print(f"Launched application: {app_data['name']} ({app_path})")
            
            QtWidgets.QMessageBox.information(self, "Launch Success", f"Launching '{app_data['name']}'...", QtWidgets.QMessageBox.StandardButton.Ok)

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Launch Error", f"Failed to launch '{app_data['name']}' at {app_path}:\n{e}", QtWidgets.QMessageBox.StandardButton.Ok)

    def remove_selected_app(self):
        if not self.selected_app_data:
            QtWidgets.QMessageBox.warning(self, "Selection Error", "Please select an application to remove by clicking its button.", QtWidgets.QMessageBox.StandardButton.Ok)
            return
            
        app_data = self.selected_app_data
        
        reply = QtWidgets.QMessageBox.question(self, 'Confirm Removal',
            f"Are you sure you want to remove the shortcut for '{app_data['name']}'?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No, 
            QtWidgets.QMessageBox.StandardButton.No)

        if reply == QtWidgets.QMessageBox.StandardButton.Yes:
            self.apps = [app for app in self.apps if app['path'] != app_data['path']]
            self.selected_app_data = None
            self.btn_remove.setEnabled(False)
            self._save_apps()
            self.refresh_app_list()
            QtWidgets.QMessageBox.information(self, "Removed", f"Shortcut for '{app_data['name']}' removed.", QtWidgets.QMessageBox.StandardButton.Ok)

    def clear_layout(self, layout):
        if layout is not None:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()
                elif item.layout() is not None:
                    self.clear_layout(item.layout())

    def refresh_app_list(self):
        self.clear_layout(self.app_buttons_layout)
        
        for app in self.apps:
            btn = self.create_app_button(app)
            self.app_buttons_layout.addWidget(btn)
        
        self.selected_app_data = None
        self.btn_remove.setEnabled(False)

    def _save_apps(self):
        self.settings_manager.settings['apps'] = self.apps
        self.settings_manager.save_settings()

class NetstatTab(QtWidgets.QWidget):
    
    activity_signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.selected_connection = None
        self.activity_signal.connect(self.update_console)
        self.is_windows = platform.system() == "Windows"
        self.init_ui()
        self.refresh_connections()

    def init_ui(self):
        main_layout = QtWidgets.QHBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        left_pane = QtWidgets.QVBoxLayout()
        
        self.lbl_conn_details = QtWidgets.QLabel("Select a connection for details...")
        self.lbl_conn_details.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff8800; padding: 10px; background: rgba(0,0,0,100); border-radius: 8px;")
        left_pane.addWidget(self.lbl_conn_details)
        
        left_pane.addWidget(QtWidgets.QLabel("Activity Console"))
        self.console = QtWidgets.QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet("background: rgba(0, 0, 0, 180); color: #00ff00; border: 1px solid #00ff00; border-radius: 5px; padding: 5px;")
        left_pane.addWidget(self.console)
        
        main_layout.addLayout(left_pane, 1) 

        right_pane = QtWidgets.QVBoxLayout()
        
        btn_refresh = QtWidgets.QPushButton("Refresh Connections")
        btn_refresh.clicked.connect(self.refresh_connections)
        right_pane.addWidget(btn_refresh)

        self.conn_list = QtWidgets.QListWidget()
        self.conn_list.setStyleSheet("background: rgba(0, 0, 0, 150); color: #fff; border-radius: 5px; padding: 5px; font-family: 'Consolas', 'Courier New', monospace;")
        self.conn_list.itemClicked.connect(self.conn_selected)
        right_pane.addWidget(self.conn_list)

        button_layout = QtWidgets.QHBoxLayout()
        
        self.btn_ping = QtWidgets.QPushButton("Ping IP")
        self.btn_traceroute = QtWidgets.QPushButton("Traceroute")
        self.btn_copy_ip = QtWidgets.QPushButton("Copy Remote IP")
        self.btn_kill = QtWidgets.QPushButton("Kill Process")
        self.btn_geolocate = QtWidgets.QPushButton("Geolocate IP")
        
        self.btn_kill.setStyleSheet("background: #ff4444; color: white;")
        
        for btn in [self.btn_ping, self.btn_traceroute, self.btn_copy_ip, self.btn_kill, self.btn_geolocate]:
            btn.setEnabled(False) 
            button_layout.addWidget(btn)
        
        self.btn_ping.clicked.connect(lambda: threading.Thread(target=self.run_network_tool, args=("ping",), daemon=True).start())
        self.btn_traceroute.clicked.connect(lambda: threading.Thread(target=self.run_network_tool, args=("traceroute",), daemon=True).start())
        self.btn_copy_ip.clicked.connect(self.copy_remote_ip)
        self.btn_kill.clicked.connect(self.kill_process)
        self.btn_geolocate.clicked.connect(self.geolocate_ip) 

        right_pane.addLayout(button_layout)
        
        main_layout.addLayout(right_pane, 2) 

    @QtCore.pyqtSlot(str)
    def update_console(self, text):
        self.console.append(text)

    def refresh_connections(self):
        self.conn_list.clear()
        connections = get_active_connections()
        for item in connections:
            self.conn_list.addItem(item)
            
        self.conn_list.setCurrentRow(-1) 
        self.selected_connection = None
        self.update_selection_ui()
        self.update_console(f"--- Refreshed list ({len(connections)} entries) at {datetime.datetime.now().strftime('%H:%M:%S')} ---")


    def conn_selected(self, item):
        self.selected_connection = item.data(QtCore.Qt.ItemDataRole.UserRole)
        self.update_selection_ui()

    def update_selection_ui(self):
        conn = self.selected_connection
        
        if conn:
            status_text = f"PID: {conn.pid} | Process: {conn.pname} | Status: {conn.status}"
            self.lbl_conn_details.setText(f"Local: {conn.local_addr}\nRemote: {conn.remote_addr}\n{status_text}")
            
            has_remote_ip = conn.remote_ip is not None and conn.remote_ip != '0.0.0.0'
            self.btn_ping.setEnabled(has_remote_ip)
            self.btn_traceroute.setEnabled(has_remote_ip)
            self.btn_copy_ip.setEnabled(has_remote_ip)
            self.btn_geolocate.setEnabled(has_remote_ip)
            self.btn_kill.setEnabled(conn.pid is not None and conn.pid != 0)
        else:
            self.lbl_conn_details.setText("Select a connection for details...")
            for btn in [self.btn_ping, self.btn_traceroute, self.btn_copy_ip, self.btn_kill, self.btn_geolocate]:
                btn.setEnabled(False)


    def run_network_tool(self, tool):
        if not self.selected_connection: return
        ip = self.selected_connection.remote_ip
        if not ip or ip == '0.0.0.0':
            self.activity_signal.emit(f"[ERROR] Cannot run {tool}: No remote IP selected.")
            return

        self.activity_signal.emit(f"\n--- Running {tool} on {ip} ---")
        
        if self.is_windows:
            cmd = ["ping", "-n", "4", ip] if tool == "ping" else ["tracert", ip]
        else:
            cmd = ["ping", "-c", "4", ip] if tool == "ping" else ["traceroute", ip]
            
        try:
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            output = process.stdout
            if process.stderr:
                output += f"\n[Stderr]: {process.stderr}"
                
            self.activity_signal.emit(output.strip())
            
        except subprocess.TimeoutExpired:
             self.activity_signal.emit(f"[{tool.upper()} ERROR] Command timed out after 10 seconds.")
        except Exception as e:
            self.activity_signal.emit(f"[{tool.upper()} ERROR] Failed to run command: {e}")

    def copy_remote_ip(self):
        if not self.selected_connection or not self.selected_connection.remote_ip: return
        
        clipboard = QtGui.QGuiApplication.clipboard()
        clipboard.setText(self.selected_connection.remote_ip)
        self.activity_signal.emit(f"[INFO] Copied IP: {self.selected_connection.remote_ip} to clipboard.")

    def geolocate_ip(self):
        if not self.selected_connection or not self.selected_connection.remote_ip: return
        
        ip = self.selected_connection.remote_ip
        if ip in ("127.0.0.1", get_local_ip()):
            self.activity_signal.emit(f"[INFO] Cannot geolocate local/loopback IP: {ip}")
            return
            
        controller = self.parentWidget().parentWidget()
        
        if hasattr(controller, 'geolocate_widget'):
            tab_index = controller.tabs.indexOf(controller.geolocate_widget)
            if tab_index != -1:
                controller.tabs.setCurrentIndex(tab_index)
                controller.geolocate_widget.ip_input.setText(ip)
                controller.geolocate_widget.start_geolocate()
                self.activity_signal.emit(f"[INFO] Sent IP: {ip} to Geolocate tab for lookup.")
                return

        url = f"https://www.iplocation.net/ip-lookup?query={ip}"
        QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))
        self.activity_signal.emit(f"[INFO] Opening browser for geolocation lookup of {ip}...")


    def kill_process(self):
        if not self.selected_connection: return
        pid = self.selected_connection.pid
        pname = self.selected_connection.pname

        if not pid or pid == 0:
            self.activity_signal.emit("[ERROR] Cannot kill process: PID is zero or missing.")
            return
        
        try:
            p = psutil.Process(pid)
            p.terminate()
            self.activity_signal.emit(f"[WARNING] Attempted to terminate PID {pid} ({pname})...")
            threading.Timer(1, self.refresh_connections).start()
        except psutil.NoSuchProcess:
            self.activity_signal.emit(f"[ERROR] Process PID {pid} ({pname}) not found. Already terminated?")
        except psutil.AccessDenied:
            self.activity_signal.emit(f"[FATAL] Access denied: Cannot terminate PID {pid} ({pname}). Run as administrator.")
        except Exception as e:
            self.activity_signal.emit(f"[ERROR] Failed to terminate PID {pid}: {e}")

class ProcessesTab(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.refresh_processes()
        
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.refresh_processes)
        self.timer.start(5000) 

    def init_ui(self):
        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        top_controls = QtWidgets.QHBoxLayout()
        
        self.search_input = QtWidgets.QLineEdit()
        self.search_input.setPlaceholderText("Filter processes by name or PID...")
        self.search_input.textChanged.connect(self.filter_processes)
        top_controls.addWidget(self.search_input)
        
        btn_refresh = QtWidgets.QPushButton("Refresh")
        btn_refresh.clicked.connect(self.refresh_processes)
        top_controls.addWidget(btn_refresh)
        
        self.btn_kill = QtWidgets.QPushButton("Kill Selected Process")
        self.btn_kill.setStyleSheet("background: #ff4444; color: white;")
        self.btn_kill.clicked.connect(self.kill_selected_process)
        self.btn_kill.setEnabled(False) 
        top_controls.addWidget(self.btn_kill)
        
        main_layout.addLayout(top_controls)

        self.process_table = QtWidgets.QTableWidget()
        self.process_table.setColumnCount(6)
        self.process_table.setHorizontalHeaderLabels(["PID", "Name", "CPU %", "Memory %", "User", "Start Time"])
        self.process_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.process_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.process_table.setStyleSheet("background: rgba(0, 0, 0, 150); color: #fff; border-radius: 5px; padding: 5px; font-family: 'Consolas', 'Courier New', monospace;")

        self.process_table.setSortingEnabled(True)
        
        self.process_table.itemSelectionChanged.connect(self.update_kill_button_state)

        main_layout.addWidget(self.process_table)

    def get_selected_pid(self):
        selected_indexes = self.process_table.selectedIndexes()
        if not selected_indexes:
            return None
        
        row = selected_indexes[0].row()
        
        pid_item = self.process_table.item(row, 0)
        if pid_item:
            return pid_item.data(QtCore.Qt.ItemDataRole.DisplayRole)
        return None

    def refresh_processes(self):
        selected_pid = self.get_selected_pid()

        self.process_table.setSortingEnabled(False) 
        self.process_table.setRowCount(0)
        
        process_list = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username', 'create_time']):
            try:
                info = p.info
                start_time_dt = datetime.datetime.fromtimestamp(info['create_time'])
                start_time_str = start_time_dt.strftime("%Y-%m-%d %H:%M:%S")

                process_list.append([
                    info['pid'], 
                    info['name'], 
                    round(info['cpu_percent'], 1), 
                    round(info['memory_percent'], 1), 
                    info['username'] or 'N/A', 
                    start_time_str
                ])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        self.process_table.setRowCount(len(process_list))
        
        row_to_select = -1 
        
        for row, data in enumerate(process_list):
            for col, item_data in enumerate(data):
                if col in [0, 2, 3]: 
                    item = QtWidgets.QTableWidgetItem()
                    item.setData(QtCore.Qt.ItemDataRole.DisplayRole, item_data)
                    
                    if col == 0 and item_data == selected_pid:
                        row_to_select = row
                else: 
                    item = QtWidgets.QTableWidgetItem(str(item_data))
                    
                self.process_table.setItem(row, col, item)

        if row_to_select != -1:
            item = self.process_table.item(row_to_select, 0)
            if item:
                self.process_table.setCurrentItem(item)
                self.process_table.scrollToItem(item, QtWidgets.QAbstractItemView.ScrollHint.EnsureVisible)
        else:
            self.process_table.setCurrentItem(None)

        self.process_table.resizeColumnsToContents()
        header = self.process_table.horizontalHeader()
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.Stretch) 
        
        self.process_table.setSortingEnabled(True) 

        self.update_kill_button_state()
            
    def update_kill_button_state(self):
        self.btn_kill.setEnabled(len(self.process_table.selectedItems()) > 0)

    def filter_processes(self, text):
        search_text = text.lower()
        self.process_table.clearSelection() 
        self.update_kill_button_state()

        for i in range(self.process_table.rowCount()):
            name_item = self.process_table.item(i, 1)
            pid_item = self.process_table.item(i, 0)
            
            match_name = name_item and search_text in name_item.text().lower()
            
            pid_match = False
            if pid_item:
                pid_data = pid_item.data(QtCore.Qt.ItemDataRole.DisplayRole)
                if isinstance(pid_data, (int, float)):
                    pid_str = str(int(pid_data))
                    pid_match = search_text in pid_str

            is_visible = match_name or pid_match
            self.process_table.setRowHidden(i, not is_visible)
            
    def kill_selected_process(self):
        selected_rows = set(index.row() for index in self.process_table.selectedIndexes())
        if not selected_rows: return

        row = list(selected_rows)[0]
        
        pid_item = self.process_table.item(row, 0)
        name_item = self.process_table.item(row, 1)
        
        if not pid_item or not name_item: return

        pid = pid_item.data(QtCore.Qt.ItemDataRole.DisplayRole)
        pname = name_item.text()

        reply = QtWidgets.QMessageBox.question(self, 'Confirm Termination',
            f"Are you sure you want to terminate PID {pid} ({pname})?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No, 
            QtWidgets.QMessageBox.StandardButton.No)

        if reply == QtWidgets.QMessageBox.StandardButton.Yes:
            try:
                p = psutil.Process(pid)
                p.terminate()
                QtWidgets.QMessageBox.information(self, "Process Killed", f"Successfully terminated PID {pid} ({pname}).", QtWidgets.QMessageBox.StandardButton.Ok)
                QtCore.QTimer.singleShot(500, self.refresh_processes)
            except psutil.NoSuchProcess:
                QtWidgets.QMessageBox.warning(self, "Error", f"Process PID {pid} not found. Already terminated?", QtWidgets.QMessageBox.StandardButton.Ok)
            except psutil.AccessDenied:
                QtWidgets.QMessageBox.critical(self, "Fatal Error", f"Access denied: Cannot terminate PID {pid} ({pname}). Run as administrator.", QtWidgets.QMessageBox.StandardButton.Ok)
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Error", f"Failed to terminate PID {pid}: {e}", QtWidgets.QMessageBox.StandardButton.Ok)

class GeolocateTab(QtWidgets.QWidget):
    
    geolocate_signal = QtCore.pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.geolocate_signal.connect(self.display_results)
        self.init_ui()

    def init_ui(self):
        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)

        input_frame = QtWidgets.QFrame()
        input_frame.setStyleSheet("background: rgba(0,0,0,100); border-radius: 10px; padding: 10px;")
        input_layout = QtWidgets.QHBoxLayout(input_frame)
        
        self.ip_input = QtWidgets.QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP Address")
        self.ip_input.setStyleSheet("color: #fff;")
        input_layout.addWidget(self.ip_input)
        
        self.btn_geolocate = QtWidgets.QPushButton("Geolocate IP")
        self.btn_geolocate.clicked.connect(self.start_geolocate)
        input_layout.addWidget(self.btn_geolocate)
        
        main_layout.addWidget(input_frame)
        
        results_label = QtWidgets.QLabel("Geolocation Results & Map Viewer")
        results_label.setStyleSheet("font-size: 18px; font-weight: bold; margin-top: 15px; padding: 5px;")
        main_layout.addWidget(results_label)

        self.results_text = QtWidgets.QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("background: rgba(0, 0, 0, 180); color: #00ff00; border: 1px solid #00ff00; border-radius: 5px; padding: 10px;")
        main_layout.addWidget(self.results_text, 1) 
        
        quick_action_layout = QtWidgets.QHBoxLayout()
        btn_self_ip = QtWidgets.QPushButton("Use My Public IP")
        btn_self_ip.clicked.connect(self.set_public_ip)
        
        btn_clear = QtWidgets.QPushButton("Clear Results")
        btn_clear.setStyleSheet("background: #ff8800; color: white;")
        btn_clear.clicked.connect(self.results_text.clear)
        
        quick_action_layout.addWidget(btn_self_ip)
        quick_action_layout.addWidget(btn_clear)
        main_layout.addLayout(quick_action_layout)

    def set_public_ip(self):
        self.ip_input.setText(get_public_ip())
        
    def start_geolocate(self):
        ip = self.ip_input.text().strip()
        
        if not ip:
            ip = get_public_ip()
            self.ip_input.setText(ip)

        if not ip or ip in ("N/A", "Fetching...", "127.0.0.1"):
            self.display_results({"status": "fail", "message": "Invalid or local IP for geolocation."})
            return
            
        self.results_text.append(f"--- Geolocating IP: {ip} ---")
        self.btn_geolocate.setEnabled(False)
        threading.Thread(target=self._run_geolocate_thread, args=(ip,), daemon=True).start()

    def _run_geolocate_thread(self, ip):
        data = _fetch_geolocation_data(ip)
        self.geolocate_signal.emit(data)

    @QtCore.pyqtSlot(dict)
    def display_results(self, data):
        self.btn_geolocate.setEnabled(True)
        ip = self.ip_input.text().strip()
        
        if data.get("status") == "success":
            output = f"""
[GEOLOCATION SUCCESS]
IP Address: {data.get('query', ip)}
Status: {data.get('status', 'N/A')}

Country: {data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})
Region/State: {data.get('regionName', 'N/A')} ({data.get('region', 'N/A')})
City: {data.get('city', 'N/A')}
Zip Code: {data.get('zip', 'N/A')}

Latitude: {data.get('lat', 'N/A')}
Longitude: {data.get('lon', 'N/A')}
Timezone: {data.get('timezone', 'N/A')}
ISP: {data.get('isp', 'N/A')}
Organization: {data.get('org', 'N/A')}
AS: {data.get('as', 'N/A')}
            """.strip()
        elif data.get("status") == "fail":
            output = f"[GEOLOCATION FAILED]\nIP: {ip}\nReason: {data.get('message', 'Could not get data')}"
        else:
            output = f"[GEOLOCATION FAILED]\nIP: {ip}\nReason: Invalid response or API error."

        self.results_text.append(output)

        if data.get('lat') and data.get('lon') and data.get('status') == 'success':
             map_url = f"https://www.google.com/maps/search/?api=1&query={data['lat']},{data['lon']}"
             self.results_text.append(f"\n[INFO] Opening browser to Google Maps for visual location of {ip}...")
             QtGui.QDesktopServices.openUrl(QtCore.QUrl(map_url))


class CortexSuite(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.settings_manager = SettingsManager(SETTINGS_FILE)
        self.settings = self.settings_manager.settings
        
        try:
            x, y, w, h = map(int, self.settings.get('window_geometry', "100,100,1400,850").split(','))
            self.setGeometry(x, y, w, h)
        except:
             self.setGeometry(100, 100, 1400, 850)
        
        self.setWindowTitle("Cortex Suite")
        self.dragPos = None 
        self.is_maximized = False
        self.net_timer = QtCore.QTimer() 

        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setWindowFlags(QtCore.Qt.WindowType.FramelessWindowHint)
        
        self.main_widget = QtWidgets.QWidget()
        self.main_widget.setObjectName("main_widget_container")
        self.main_layout = QtWidgets.QVBoxLayout(self.main_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        self.setCentralWidget(self.main_widget)
        
        self.setStyleSheet(self._get_stylesheet())
        
        self.create_custom_title_bar()
        
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setUsesScrollButtons(False)
        self.main_layout.addWidget(self.tabs)
        
        self.home_tab()
        self.system_tab()
        self.processes_tab() 
        self.netstat_tab() 
        self.network_tab()
        self.geolocate_tab() 
        self.apps_tab() 
        self.commands_tab()
        self.automation_tab()
        self.settings_tab() 
        
        self.setup_transparent_wallpaper()
        
        threading.Thread(target=self._fetch_public_ip_home, daemon=True).start()


    def _create_rounded_rect_mask(self, size):
        path = QtGui.QPainterPath()
        rect = QtCore.QRectF(0, 0, size.width(), size.height())
        path.addRoundedRect(rect, CORNER_RADIUS, CORNER_RADIUS)
        return QtGui.QRegion(path.toFillPolygon().toPolygon())

    def showEvent(self, event):
        self.setMask(self._create_rounded_rect_mask(self.size()))
        super().showEvent(event)

    def _get_stylesheet(self):
        return f"""
            #main_widget_container {{
                background: rgba(10, 13, 26, 100); 
                border-radius: {CORNER_RADIUS}px; 
            }}
            QWidget {{ background: transparent; }}
            
            #title_bar_frame {{
                background: rgba(10, 13, 26, 180); 
                border-top-left-radius: {CORNER_RADIUS}px;
                border-top-right-radius: {CORNER_RADIUS}px;
            }}
            
            QPushButton {{
                background: rgba(0, 240, 255, 200); 
                border-radius: 5px; padding: 8px; color: #000; font-weight: bold;
            }}
            QPushButton:hover {{ background: #fff; }}
            QLineEdit, QTextEdit {{
                background: rgba(0, 0, 0, 150); 
                color: #00f0ff; border: 1px solid #00f0ff; border-radius: 5px; padding: 5px;
            }}
            QLabel {{ color: #00f0ff; font-family: 'Segoe UI'; }}
            QListWidget {{
                background: rgba(0, 0, 0, 150);
                color: #00f0ff; border-radius: 5px; padding: 5px;
            }}
            QTableWidget {{ 
                background: rgba(0, 0, 0, 150);
                color: #00f0ff; 
                border-radius: 5px; 
                padding: 5px;
                gridline-color: rgba(0, 240, 255, 50); 
                selection-background-color: rgba(0, 240, 255, 100); 
            }}
            QTableWidget::item:selected {{
                color: #fff;
            }}
            QHeaderView::section {{ 
                background-color: rgba(0, 240, 255, 50);
                color: #00f0ff;
                padding: 4px;
                border: 1px solid rgba(0, 240, 255, 100);
            }}
            QCheckBox {{ color: #00f0ff; }}

            .big_stat_label {{ font-size: 24px; font-weight: bold; color: #00f0ff; }}
            
            QTabWidget::pane {{ border: 0; }}
            
            QTabWidget::tab-bar {{
                margin-top: 5px; 
                alignment: center; 
                padding-left: 100px; 
                padding-right: 100px;
            }}
            
            QTabBar::tab {{
                background: rgba(10, 13, 26, 150);
                color: #00f0ff; 
                padding: 10px 30px; 
                
                margin-left: 8px; 
                margin-right: 8px;
                
                border-radius: 10px; 
            }}
            QTabBar::tab:first {{ margin-left: 0px; }}
            QTabBar::tab:last {{ margin-right: 0px; }}
            
            QTabBar::tab:selected {{ 
                background: rgba(0, 240, 255, 50); 
                font-weight: bold;
            }}
        """

    def setup_transparent_wallpaper(self):
        if hasattr(self, 'wallpaper_widget'):
            self.wallpaper_widget.deleteLater()

        self.wallpaper_widget = QtWidgets.QWidget(self)
        self.wallpaper_widget.setGeometry(self.rect())
        self.wallpaper_widget.lower() 
        
        path = self.settings.get('wallpaper_path', DEFAULT_WALLPAPER_PATH)
        
        if os.path.exists(path):
            print(f"Loading wallpaper: {path}")
            self.wallpaper_label = QtWidgets.QLabel(self)
            pixmap = QtGui.QPixmap(path)
            
            self.wallpaper_label.setPixmap(pixmap.scaled(
                self.size(),
                QtCore.Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                QtCore.Qt.TransformationMode.SmoothTransformation
            ))
            self.wallpaper_label.setGeometry(self.rect())
            
            self.blur_effect = QtWidgets.QGraphicsBlurEffect() 
            self.blur_effect.setBlurRadius(self.settings.get('blur_radius', DEFAULT_BLUR_RADIUS))
            self.wallpaper_label.setGraphicsEffect(self.blur_effect)
            
            self.wallpaper_label.show()
            
            self.wallpaper_label.setParent(self.wallpaper_widget)
            
            self.wallpaper_widget.show()
        else:
            print(f"Wallpaper not found at: {path}")
            self.wallpaper_widget.hide()

    def resizeEvent(self, event):
        if not self.is_maximized:
            self.setMask(self._create_rounded_rect_mask(self.size()))
        
        if hasattr(self, 'wallpaper_widget'):
            self.wallpaper_widget.setGeometry(self.rect())
            if hasattr(self, 'wallpaper_label'):
                self.wallpaper_label.setGeometry(self.rect())
                path = self.settings.get('wallpaper_path', DEFAULT_WALLPAPER_PATH)
                if os.path.exists(path):
                    pix = QtGui.QPixmap(path)
                    self.wallpaper_label.setPixmap(pix.scaled(
                        self.size(),
                        QtCore.Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                        QtCore.Qt.TransformationMode.SmoothTransformation
                    ))
        super().resizeEvent(event)

    def closeEvent(self, event):
        if hasattr(self, 'timer') and self.timer.isActive():
            self.timer.stop()
        if hasattr(self, 'net_timer') and self.net_timer.isActive():
            self.net_timer.stop()
            
        if hasattr(self, 'processes_widget') and hasattr(self.processes_widget, 'timer') and self.processes_widget.timer.isActive():
            self.processes_widget.timer.stop()
        
        geom = self.geometry()
        self.settings['window_geometry'] = f"{geom.x()},{geom.y()},{geom.width()},{geom.height()}"
        self.settings_manager.save_settings()
        
        super().closeEvent(event)

    def create_custom_title_bar(self):
        self.title_bar = QtWidgets.QFrame()
        self.title_bar.setObjectName("title_bar_frame")
        self.title_bar.setFixedHeight(35)
        layout = QtWidgets.QHBoxLayout(self.title_bar)
        layout.setContentsMargins(10,0,10,0)
        
        layout.addWidget(QtWidgets.QLabel("CORTEX SUITE"))
        layout.addStretch(1)
        
        btn_min = QtWidgets.QPushButton("-")
        btn_min.setFixedSize(30,25)
        btn_min.clicked.connect(self.showMinimized)
        layout.addWidget(btn_min)
        
        btn_max = QtWidgets.QPushButton("[]")
        btn_max.setFixedSize(30,25)
        btn_max.clicked.connect(self.toggle_max)
        layout.addWidget(btn_max)
        
        btn_close = QtWidgets.QPushButton("X")
        btn_close.setFixedSize(30,25)
        btn_close.setStyleSheet("background: #ff4444; color: white;")
        btn_close.clicked.connect(self.close)
        layout.addWidget(btn_close)
        
        self.main_layout.addWidget(self.title_bar)

    def toggle_max(self):
        if self.is_maximized:
            self.showNormal()
            self.is_maximized = False
        else:
            self.showMaximized()
            self.is_maximized = True
            self.setMask(QtGui.QRegion())

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            self.dragPos = event.globalPosition().toPoint()
            event.accept()

    def mouseMoveEvent(self, event):
        if self.dragPos:
            delta = event.globalPosition().toPoint() - self.dragPos
            self.move(self.pos() + delta)
            self.dragPos = event.globalPosition().toPoint()
            event.accept()

    def mouseReleaseEvent(self, event):
        self.dragPos = None

    def home_tab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        
        grid = QtWidgets.QGridLayout()
        grid.setSpacing(15)
        
        frame1 = QtWidgets.QFrame()
        frame1.setStyleSheet("background: rgba(0,0,0,100); border-radius: 15px;")
        l1 = QtWidgets.QVBoxLayout(frame1)
        
        self.lbl_cpu = QtWidgets.QLabel("CPU: ...")
        self.lbl_ram = QtWidgets.QLabel("RAM: ...")
        self.lbl_time = QtWidgets.QLabel()
        
        for w in [self.lbl_cpu, self.lbl_ram, self.lbl_time]: 
            w.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            w.setStyleSheet("font-size: 30px; font-weight: bold;")
            l1.addWidget(w)
            
        grid.addWidget(frame1, 0, 0, 1, 2) 

        frame2 = QtWidgets.QFrame()
        frame2.setStyleSheet("background: rgba(0,0,0,100); border-radius: 15px; padding: 10px;")
        l2 = QtWidgets.QVBoxLayout(frame2)
        
        l2.addWidget(QtWidgets.QLabel("System Information"))
        self.lbl_sys_info = QtWidgets.QLabel(f"OS: {platform.system()} {platform.release()}")
        self.lbl_gpu_info = QtWidgets.QLabel(f"GPU: {get_gpu_info()}")
        self.lbl_uptime = QtWidgets.QLabel("Uptime: ...")

        for w in [self.lbl_sys_info, self.lbl_gpu_info, self.lbl_uptime]: 
            w.setStyleSheet("font-size: 16px;")
            l2.addWidget(w)

        l2.addStretch(1)
        grid.addWidget(frame2, 1, 0)
        
        frame3 = QtWidgets.QFrame()
        frame3.setStyleSheet("background: rgba(0,0,0,100); border-radius: 15px; padding: 10px;")
        l3 = QtWidgets.QVBoxLayout(frame3)
        
        l3.addWidget(QtWidgets.QLabel("Network Status"))
        self.lbl_home_local_ip = QtWidgets.QLabel(f"Local IP: {get_local_ip()}")
        self.lbl_home_public_ip = QtWidgets.QLabel("Public IP: Fetching...")
        
        l3.addWidget(QtWidgets.QLabel("Storage Status"))
        self.lbl_home_disk = QtWidgets.QLabel(f"Disk (C:\\): {get_disk_usage()}")

        for w in [self.lbl_home_local_ip, self.lbl_home_public_ip, self.lbl_home_disk]: 
            w.setStyleSheet("font-size: 16px;")
            l3.addWidget(w)

        l3.addStretch(1)
        grid.addWidget(frame3, 1, 1)

        layout.addLayout(grid, 1)
        layout.addStretch(0)
        
        self.tabs.addTab(tab, "Home")

        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)

    def _fetch_public_ip_home(self):
        ip = get_public_ip()
        QtCore.QMetaObject.invokeMethod(self.lbl_home_public_ip, "setText", QtCore.Qt.ConnectionType.QueuedConnection, QtCore.Q_ARG(str, f"Public IP: {ip}"))


    def update_stats(self):
        try:
            self.lbl_cpu.setText(f"CPU: {psutil.cpu_percent()}%")
            self.lbl_ram.setText(f"RAM: {psutil.virtual_memory().percent}%")
            self.lbl_time.setText(datetime.datetime.now().strftime("%H:%M:%S"))
            self.lbl_uptime.setText(f"Uptime: {str(datetime.timedelta(seconds=int(time.time() - psutil.boot_time())))}")
            self.lbl_home_disk.setText(f"Disk (C:\\): {get_disk_usage()}")
            
            if self.tabs.currentIndex() == 1:
                self.update_system_full()
            
            tab_names = [self.tabs.tabText(i) for i in range(self.tabs.count())]
            if "Network" in tab_names and self.tabs.currentIndex() == tab_names.index("Network"):
                self.update_net_io()

        except RuntimeError as e:
            if "has been deleted" in str(e):
                if self.timer.isActive():
                    print(f"Caught RuntimeError ({e}): Stopping stats timer.")
                    self.timer.stop()
            else:
                raise 

    def system_tab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        
        container = QtWidgets.QFrame()
        container.setStyleSheet("background: rgba(0,0,0,100); border-radius: 15px; padding: 20px;")
        self.sys_layout_grid = QtWidgets.QGridLayout(container)
        self.sys_layout_grid.setSpacing(15)

        self.lbl_sys_os = QtWidgets.QLabel(f"OS: {platform.system()} {platform.release()}")
        self.lbl_sys_cpu_freq = QtWidgets.QLabel("CPU Freq: ...")
        self.lbl_sys_cores = QtWidgets.QLabel(f"Cores: {psutil.cpu_count(logical=False)} (Phys) / {psutil.cpu_count()} (Log)")
        self.lbl_sys_mem_avail = QtWidgets.QLabel("RAM Available: ...")
        self.lbl_sys_disk = QtWidgets.QLabel("Disk Usage: ...") 

        self.sys_layout_grid.addWidget(QtWidgets.QLabel("--- OS & CPU ---"), 0, 0, 1, 2)
        self.sys_layout_grid.addWidget(self.lbl_sys_os, 1, 0, 1, 2)
        self.sys_layout_grid.addWidget(self.lbl_sys_cores, 2, 0)
        self.sys_layout_grid.addWidget(self.lbl_sys_cpu_freq, 2, 1)

        self.sys_layout_grid.addWidget(QtWidgets.QLabel("--- Memory & Storage ---"), 3, 0, 1, 2)
        self.sys_layout_grid.addWidget(self.lbl_sys_mem_avail, 4, 0)
        self.sys_layout_grid.addWidget(self.lbl_sys_disk, 5, 0, 1, 2)

        self.sys_layout_grid.setColumnStretch(0, 1)
        self.sys_layout_grid.setColumnStretch(1, 1)
        
        layout.addWidget(container)
        layout.addStretch(1)
        self.tabs.addTab(tab, "System")

    def update_system_full(self):
        if not hasattr(self, 'lbl_sys_cpu_freq') or not self.lbl_sys_cpu_freq.parentWidget(): return
        
        freq = psutil.cpu_freq()
        if freq:
            self.lbl_sys_cpu_freq.setText(f"CPU Freq: {freq.current:.0f} Mhz")
        
        mem = psutil.virtual_memory()
        self.lbl_sys_mem_avail.setText(f"RAM Available: {round(mem.available/1024/1024/1024, 2)} GB")

        disk = psutil.disk_usage(os.path.abspath(os.sep))
        self.lbl_sys_disk.setText(f"Disk Usage: {disk.percent}% ({round(disk.used/1e9, 1)}/{round(disk.total/1e9, 1)} GB)")

    def processes_tab(self):
        self.processes_widget = ProcessesTab()
        self.tabs.addTab(self.processes_widget, "Processes")

    def netstat_tab(self):
        self.netstat_widget = NetstatTab()
        self.tabs.addTab(self.netstat_widget, "Netstat")

    def network_tab(self):
            tab = QtWidgets.QWidget()
            layout = QtWidgets.QVBoxLayout(tab)
            
            container = QtWidgets.QFrame()
            container.setStyleSheet("background: rgba(0,0,0,100); border-radius: 15px; padding: 20px;")
            vbox = QtWidgets.QVBoxLayout(container)
            
            self.lbl_net_local = QtWidgets.QLabel(f"Local IP: {get_local_ip()}")
            self.lbl_net_pub = QtWidgets.QLabel("Public IP: Fetching...")
            self.lbl_net_io_sent = QtWidgets.QLabel("Total Sent: ...")
            self.lbl_net_io_recv = QtWidgets.QLabel("Total Received: ...")
            
            for w in [self.lbl_net_local, self.lbl_net_pub, self.lbl_net_io_sent, self.lbl_net_io_recv]:
                w.setStyleSheet("font-size: 20px; padding: 5px;")
                vbox.addWidget(w)
            
            vbox.addStretch(1)

            layout.addWidget(container)
            
            table_label = QtWidgets.QLabel("Network Interface Details")
            table_label.setStyleSheet("font-size: 18px; font-weight: bold; margin-top: 15px; padding: 5px;")
            layout.addWidget(table_label)
            
            self.net_if_table = QtWidgets.QTableWidget()
            self.net_if_table.setColumnCount(7)
            self.net_if_table.setHorizontalHeaderLabels(["Interface", "Status", "Speed", "IPv4 Address", "MAC Address", "Sent", "Received"])
            self.net_if_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
            self.net_if_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
            self.net_if_table.setStyleSheet("background: rgba(0, 0, 0, 150); color: #fff; border-radius: 5px; padding: 5px; gridline-color: rgba(0, 240, 255, 50);")
            
            layout.addWidget(self.net_if_table, 1) 

            btn_refresh = QtWidgets.QPushButton("Refresh Public IP")
            btn_refresh.clicked.connect(lambda: threading.Thread(target=self._fetch_public_ip_network_tab, daemon=True).start())
            layout.addWidget(btn_refresh)
            
            self.tabs.addTab(tab, "Network")
            
            threading.Thread(target=self._fetch_public_ip_network_tab, daemon=True).start()

    def geolocate_tab(self):
        self.geolocate_widget = GeolocateTab()
        self.tabs.addTab(self.geolocate_widget, "Geolocate")
    
    def apps_tab(self):
        self.apps_widget = AppsTab(self.settings_manager)
        self.tabs.addTab(self.apps_widget, "Apps") 

    def _fetch_public_ip_network_tab(self):
        ip = get_public_ip()
        QtCore.QMetaObject.invokeMethod(self.lbl_net_pub, "setText", QtCore.Qt.ConnectionType.QueuedConnection, QtCore.Q_ARG(str, f"Public IP: {ip}"))
        if hasattr(self, 'lbl_home_public_ip'):
            QtCore.QMetaObject.invokeMethod(self.lbl_home_public_ip, "setText", QtCore.Qt.ConnectionType.QueuedConnection, QtCore.Q_ARG(str, f"Public IP: {ip}"))


    def update_net_io(self):
        if hasattr(self, 'lbl_net_io_sent') and self.lbl_net_io_sent.parentWidget():
            io = psutil.net_io_counters()
            self.lbl_net_io_sent.setText(f"Total Sent: {round(io.bytes_sent/1024/1024, 1)} MB")
            self.lbl_net_io_recv.setText(f"Total Received: {round(io.bytes_recv/1024/1024, 1)} MB")
        
        if hasattr(self, 'net_if_table') and self.net_if_table.parentWidget():
            interface_stats = get_network_interface_stats()
            self.net_if_table.setRowCount(len(interface_stats))
            
            for row, stats in enumerate(interface_stats):
                data = [
                    stats['name'], 
                    stats['status'], 
                    stats['speed'], 
                    stats['ipv4'], 
                    stats['mac'], 
                    stats['sent'], 
                    stats['recv']
                ]
                
                for col, item_data in enumerate(data):
                    item = QtWidgets.QTableWidgetItem(str(item_data))
                    self.net_if_table.setItem(row, col, item)

            self.net_if_table.resizeColumnsToContents()
            header = self.net_if_table.horizontalHeader()
            header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents) 
            header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeMode.Stretch) 


    def commands_tab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        
        self.cmd_input = QtWidgets.QLineEdit()
        self.cmd_input.setPlaceholderText("Enter command")
        self.cmd_input.returnPressed.connect(self.run_command)
        layout.addWidget(self.cmd_input)
        
        self.cmd_output = QtWidgets.QTextEdit()
        self.cmd_output.setReadOnly(True)
        layout.addWidget(self.cmd_output)
        
        self.tabs.addTab(tab, "Commands")

    def run_command(self):
        cmd = self.cmd_input.text()
        if not cmd: return
        self.cmd_output.append(f"> {cmd}")
        self.cmd_input.clear()
        threading.Thread(target=self._execute_cmd, args=(cmd,), daemon=True).start()

    def _execute_cmd(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            output = result.stdout
            if result.stderr:
                output += f"\n[Stderr]: {result.stderr}"
            if not output and result.returncode == 0:
                output = "[Command executed successfully]"
            QtCore.QMetaObject.invokeMethod(self.cmd_output, "append", QtCore.Qt.ConnectionType.QueuedConnection, QtCore.Q_ARG(str, output))
        except Exception as e:
            QtCore.QMetaObject.invokeMethod(self.cmd_output, "append", QtCore.Qt.ConnectionType.QueuedConnection, QtCore.Q_ARG(str, f"Error: {str(e)}"))

    def automation_tab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        
        form = QtWidgets.QHBoxLayout()
        self.auto_cmd = QtWidgets.QLineEdit()
        self.auto_cmd.setPlaceholderText("Command")
        self.auto_time = QtWidgets.QLineEdit()
        self.auto_time.setPlaceholderText("HH:MM")
        
        btn_add = QtWidgets.QPushButton("Schedule")
        btn_add.clicked.connect(self.add_task)
        
        form.addWidget(self.auto_cmd)
        form.addWidget(self.auto_time)
        form.addWidget(btn_add)
        layout.addLayout(form)
        
        self.task_list_widget = QtWidgets.QListWidget()
        layout.addWidget(self.task_list_widget)
        
        btn_clear_tasks = QtWidgets.QPushButton("Clear All Scheduled Tasks")
        btn_clear_tasks.setStyleSheet("background: #ff4444; color: white;")
        btn_clear_tasks.clicked.connect(self.clear_tasks)
        layout.addWidget(btn_clear_tasks)
        
        self.tabs.addTab(tab, "Automation")
        
        self.tasks = self.settings.get('tasks', [])
        self.refresh_task_list()
        
        threading.Thread(target=self.task_runner, daemon=True).start()

    def add_task(self):
        t = self.auto_time.text()
        c = self.auto_cmd.text()
        if t and c:
            self.tasks.append({'time': t, 'cmd': c})
            self.settings['tasks'] = self.tasks
            self.settings_manager.save_settings()
            self.refresh_task_list()
            self.auto_cmd.clear()
            self.auto_time.clear()
            
    def clear_tasks(self):
        self.tasks = []
        self.settings['tasks'] = self.tasks
        self.settings_manager.save_settings()
        self.refresh_task_list()
        print("All scheduled tasks cleared.")


    def refresh_task_list(self):
        self.task_list_widget.clear()
        for item in self.tasks:
            if isinstance(item, dict):
                t_val = item.get('time', '??:??')
                c_val = item.get('cmd', 'Unknown')
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                t_val = item[0]
                c_val = item[1]
            else:
                continue
            self.task_list_widget.addItem(f"{t_val} -> {c_val}")

    def task_runner(self):
        last_run_minute = None
        while True:
            now = datetime.datetime.now()
            current_hm = now.strftime("%H:%M")
            
            if current_hm != last_run_minute:
                for item in self.tasks:
                    if isinstance(item, dict):
                        t_val = item.get('time')
                        c_val = item.get('cmd')
                    elif isinstance(item, (list, tuple)) and len(item) >= 2:
                        t_val = item[0]
                        c_val = item[1]
                    else:
                        continue
                    if t_val == current_hm:
                        print(f"Executing scheduled task: {c_val}")
                        try:
                            subprocess.Popen(c_val, shell=True)
                        except Exception as e:
                            print(f"Task failed: {e}")
                last_run_minute = current_hm
            time.sleep(1)

    def settings_tab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        
        wp_frame = QtWidgets.QFrame()
        wp_frame.setStyleSheet("background: rgba(0,0,0,100); border-radius: 15px; padding: 15px;")
        wp_layout = QtWidgets.QVBoxLayout(wp_frame)
        
        wp_layout.addWidget(QtWidgets.QLabel("Aesthetic Settings"))
        wp_layout.addWidget(QtWidgets.QPushButton("Choose Wallpaper", clicked=self.change_wallpaper))
        
        wp_layout.addWidget(QtWidgets.QLabel("Blur Radius:"))
        self.blur_slider = QtWidgets.QSlider(QtCore.Qt.Orientation.Horizontal)
        self.blur_slider.setRange(0, 50)
        self.blur_slider.setValue(self.settings.get('blur_radius', DEFAULT_BLUR_RADIUS))
        self.blur_slider.valueChanged.connect(self.update_blur)
        wp_layout.addWidget(self.blur_slider)
        
        layout.addWidget(wp_frame)

        startup_frame = QtWidgets.QFrame()
        startup_frame.setStyleSheet("background: rgba(0,0,0,100); border-radius: 15px; padding: 15px;")
        startup_layout = QtWidgets.QVBoxLayout(startup_frame)
        
        startup_layout.addWidget(QtWidgets.QLabel("Application Settings"))
        self.autostart_checkbox = QtWidgets.QCheckBox("Run Cortex Suite at Startup")
        self.autostart_checkbox.setChecked(self.settings.get('autostart', False))
        self.autostart_checkbox.stateChanged.connect(self.toggle_autostart)
        startup_layout.addWidget(self.autostart_checkbox)
        
        layout.addWidget(startup_frame)
        
        layout.addStretch(1)
        self.tabs.addTab(tab, "Settings")

    def change_wallpaper(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Wallpaper", "", "Images (*.jpg *.png)")
        if path:
            self.settings['wallpaper_path'] = path
            self.settings_manager.save_settings()
            self.setup_transparent_wallpaper()

    def update_blur(self, val):
        self.settings['blur_radius'] = val
        self.settings_manager.save_settings()
        if hasattr(self, 'blur_effect'):
            self.blur_effect.setBlurRadius(val)

    def toggle_autostart(self, state):
        is_checked = state == QtCore.Qt.CheckState.Checked
        self.settings['autostart'] = is_checked
        self.settings_manager.save_settings()


if __name__ == "__main__":
    if hasattr(QtCore.Qt.ApplicationAttribute, 'AA_EnableHighDpiScaling'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    if hasattr(QtCore.Qt.ApplicationAttribute, 'AA_UseHighDpiPixmaps'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
        
    app = QtWidgets.QApplication(sys.argv)
    window = CortexSuite()
    window.show()
    sys.exit(app.exec())