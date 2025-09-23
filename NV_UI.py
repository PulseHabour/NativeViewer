from typing import Optional, List, Dict, Any, Callable
from idaapi import require  # noqa
require('NV_Utils')  # noqa
from NV_Utils import OFFSET_TO_HASH, OFFSET_TO_LEA, FindGameBuild, FindRegisterNative, get_all_natives_from_ida  # noqa

import os
import json
import sqlite3
import datetime
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHeaderView,
    QLineEdit,
    QLabel,
    QMessageBox,
    QTabWidget,
    QFileDialog,
    QFrame,
    QProgressDialog,
    QStatusBar,
    QMenu,
    QCheckBox
)
from PySide6.QtCore import QSettings, Qt, QTimer
from PySide6.QtGui import QCursor, QClipboard


DEFAULT_REGISTER_NATIVE_NAME = "RegisterNative"
DEFAULT_DATABASE_NAME = "RDR2_Natives.db"
DEFAULT_NATIVES_JSON = "rdr3natives.json"
APP_NAME = "RDR2 Native Viewer"
APP_ORGANIZATION = "RDR2Tools"
APP_DOMAIN = "NativeViewer"
GITHUB_REPO_OWNER = "VORPCORE"
GITHUB_REPO_NAME = "RDR3natives"
GITHUB_FILE_PATH = "rdr3natives.json"
GITHUB_BRANCH = "main"
WINDOW_WIDTH = 1000
WINDOW_HEIGHT = 700


class UIHelpers:
    @staticmethod
    def section_label(text: str, tooltip: Optional[str] = None) -> QLabel:
        lbl = QLabel(text)
        if tooltip:
            lbl.setToolTip(tooltip)
        return lbl

    @staticmethod
    def separator() -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        return line

    @staticmethod
    def button(text: str, on_click: Callable[[], object], tooltip: Optional[str] = None) -> QPushButton:
        btn = QPushButton(text)
        if tooltip:
            btn.setToolTip(tooltip)
        btn.clicked.connect(lambda checked=False: on_click())
        return btn

    @staticmethod
    def ask_yes_no(parent: QWidget, title: str, text: str, *, default_yes: bool = True) -> bool:
        default = QMessageBox.StandardButton.Yes if default_yes else QMessageBox.StandardButton.No
        reply = QMessageBox.question(
            parent,
            title,
            text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            default,
        )
        return reply == QMessageBox.StandardButton.Yes

    @staticmethod
    def info(parent: QWidget, title: str, text: str) -> None:
        QMessageBox.information(
            parent, title, text, QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton)

    @staticmethod
    def warn(parent: QWidget, title: str, text: str) -> None:
        QMessageBox.warning(
            parent, title, text, QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton)

    @staticmethod
    def error(parent: QWidget, title: str, text: str) -> None:
        QMessageBox.critical(
            parent, title, text, QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton)

    @staticmethod
    def progress(parent: QWidget, title: str, label_text: str, maximum: int) -> QProgressDialog:
        dlg = QProgressDialog(label_text, "Cancel", 0, maximum, parent)
        dlg.setWindowTitle(title)
        dlg.setValue(0)
        return dlg


class NativeViewerUI(QMainWindow):
    def __init__(self, clipboard: QClipboard):
        super().__init__()
        self.clipboard: QClipboard = clipboard
        self.app = APP_DOMAIN
        self.natives: List[Dict[str, Any]] = []
        self.native_names_map: Dict[str, Dict[str, str]] = {}
        self.current_db_path: Optional[str] = None
        self.filter_timer = QTimer()
        self.filter_timer.setSingleShot(True)
        self.filter_timer.timeout.connect(self.filter_table)
        self.lastFilteredNatives: List[Dict[str, Any]] = []
        self.lastSearchText: str = ""
        self.DB = NV_DB(self)
        self.setWindowTitle(APP_NAME)
        self.setGeometry(100, 100, WINDOW_WIDTH, WINDOW_HEIGHT)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.settings = QSettings(APP_ORGANIZATION, APP_DOMAIN)
        self.load_settings()
        self.load_native_names()
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        self._setup_natives_tab()
        self._setup_settings_tab()
        self._setup_tools_tab()
        self.prompt_load_natives()

    def _setup_natives_tab(self):
        natives_tab = QWidget()
        layout = QVBoxLayout(natives_tab)
        self.tab_widget.addTab(natives_tab, "Natives")

        top_layout = QHBoxLayout()

        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText(
            "Enter hash or function name to search")
        self.search_box.textChanged.connect(self._start_filter_timer)
        search_layout.addWidget(self.search_box)

        filter_checkboxes_layout = QHBoxLayout()
        filter_checkboxes_layout.addWidget(QLabel("Filter by:"))

        self.filter_hash_cb = QCheckBox("Hash")
        self.filter_hash_cb.setChecked(True)
        self.filter_hash_cb.stateChanged.connect(self._start_filter_timer)
        filter_checkboxes_layout.addWidget(self.filter_hash_cb)

        self.filter_addr_cb = QCheckBox("Address")
        self.filter_addr_cb.setChecked(True)
        self.filter_addr_cb.stateChanged.connect(self._start_filter_timer)
        filter_checkboxes_layout.addWidget(self.filter_addr_cb)

        self.filter_name_cb = QCheckBox("Function Name")
        self.filter_name_cb.setChecked(True)
        self.filter_name_cb.stateChanged.connect(self._start_filter_timer)
        filter_checkboxes_layout.addWidget(self.filter_name_cb)

        self.filter_native_name_cb = QCheckBox("Native Name")
        self.filter_native_name_cb.setChecked(True)
        self.filter_native_name_cb.stateChanged.connect(
            self._start_filter_timer)
        filter_checkboxes_layout.addWidget(self.filter_native_name_cb)

        self.filter_namespace_cb = QCheckBox("Namespace")
        self.filter_namespace_cb.setChecked(True)
        self.filter_namespace_cb.stateChanged.connect(self._start_filter_timer)
        filter_checkboxes_layout.addWidget(self.filter_namespace_cb)

        search_container = QVBoxLayout()
        search_container.addLayout(search_layout)
        search_container.addLayout(filter_checkboxes_layout)

        top_layout.addLayout(search_container, 3)

        export_layout = QHBoxLayout()

        top_layout.addLayout(export_layout, 1)

        layout.addLayout(top_layout)

        self.data_source_label = QLabel("Data Source: Not Loaded")
        self.data_source_label.setStyleSheet("font-weight: bold; color: gray;")
        layout.addWidget(self.data_source_label)

        self.natives_table = QTableWidget()
        self.natives_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        self.natives_table.setColumnCount(6)
        self.natives_table.setHorizontalHeaderLabels(
            [
                "Hash",
                "Address",
                "Function Name",
                "Native Name",
                "Native Namespace",
                "Actions"
            ]
        )

        self.natives_table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )
        self.natives_table.customContextMenuRequested.connect(
            self.show_context_menu
        )

        verticalHeader = self.natives_table.verticalHeader()

        if verticalHeader:
            verticalHeader.setVisible(False)

        header = self.natives_table.horizontalHeader()
        if header:
            header.setSectionResizeMode(
                0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(
                1, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(
                2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(
                3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(
                4, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(
                5, QHeaderView.ResizeMode.ResizeToContents)
            header.setStretchLastSection(True)

        layout.addWidget(self.natives_table)

    def _setup_settings_tab(self):
        settings_tab = QWidget()
        layout = QVBoxLayout(settings_tab)
        self.tab_widget.addTab(settings_tab, "Settings")
        layout.addWidget(UIHelpers.section_label(
            "<b>Function Location Settings:</b>"))
        reg_name_layout = QHBoxLayout()
        reg_name_layout.addWidget(QLabel("RegisterNative Function Name:"))
        self.register_native_name_input = QLineEdit()
        self.register_native_name_input.setText(str(self.register_native_name))
        reg_name_layout.addWidget(self.register_native_name_input)
        layout.addLayout(reg_name_layout)
        layout.addWidget(UIHelpers.separator())
        layout.addWidget(UIHelpers.section_label("<b>Offset Settings:</b>"))
        hash_offset_layout = QHBoxLayout()
        hash_offset_layout.addWidget(QLabel("Offset to Hash:"))
        self.hash_offset_input = QLineEdit(f"0x{self.offset_to_hash:X}")
        hash_offset_layout.addWidget(self.hash_offset_input)
        layout.addLayout(hash_offset_layout)
        lea_offset_layout = QHBoxLayout()
        lea_offset_layout.addWidget(QLabel("Offset to LEA:"))
        self.lea_offset_input = QLineEdit(f"0x{self.offset_to_lea:X}")
        lea_offset_layout.addWidget(self.lea_offset_input)
        layout.addLayout(lea_offset_layout)

        buttons_layout = QHBoxLayout()

        save_settings_button = UIHelpers.button(
            "Save Settings", self.save_settings)
        buttons_layout.addWidget(save_settings_button)

        reset_settings_button = UIHelpers.button(
            "Reset to Defaults", self.reset_settings)
        buttons_layout.addWidget(reset_settings_button)

        layout.addLayout(buttons_layout)

        io_buttons_layout = QHBoxLayout()

        import_settings_button = UIHelpers.button(
            "Import Settings", self.import_settings)
        io_buttons_layout.addWidget(import_settings_button)

        layout.addLayout(io_buttons_layout)

        self.settings_status_label = QLabel("")
        layout.addWidget(self.settings_status_label)

        layout.addWidget(UIHelpers.separator())

        sqlite_label = UIHelpers.section_label(
            "<b>SQLite Database Operations:</b>")
        sqlite_label.setToolTip(
            "Save and load native functions to/from a SQLite database")
        layout.addWidget(sqlite_label)

        save_db_layout = QHBoxLayout()
        save_db_layout.addWidget(QLabel("Database File:"))
        self.db_file_path = QLineEdit()
        self.db_file_path.setPlaceholderText("Path to SQLite database file")
        save_db_layout.addWidget(self.db_file_path)

        browse_button = UIHelpers.button("Browse", self.DB.browse_db_file)
        save_db_layout.addWidget(browse_button)

        layout.addLayout(save_db_layout)

        db_buttons_layout = QHBoxLayout()

        save_natives_button = UIHelpers.button(
            "Save Natives to DB", lambda: self.DB.save_natives_to_db(self.natives))
        save_natives_button.setToolTip(
            "Save currently loaded native functions to the specified database file")
        db_buttons_layout.addWidget(save_natives_button)

        load_natives_button = UIHelpers.button(
            "Load Natives from DB", lambda: self.DB.load_natives_from_db())
        load_natives_button.setToolTip(
            "Load native functions from the specified database file")
        db_buttons_layout.addWidget(load_natives_button)

        layout.addLayout(db_buttons_layout)

        layout.addStretch(1)

    def _setup_tools_tab(self):

        tools_tab = QWidget()
        layout = QVBoxLayout(tools_tab)
        self.tab_widget.addTab(tools_tab, "Tools")

        load_ida_label = UIHelpers.section_label(
            "<b>Load Natives from IDA:</b>")
        load_ida_label.setToolTip(
            "Extract native function information directly from IDA Pro")
        layout.addWidget(load_ida_label)

        load_ida_layout = QHBoxLayout()
        load_ida_layout.addWidget(QLabel("RegisterNative Function:"))
        self.ida_register_name_input = QLineEdit()
        self.ida_register_name_input.setText(str(self.register_native_name))
        self.ida_register_name_input.setToolTip(
            "Name of the RegisterNative function to use for extraction")
        load_ida_layout.addWidget(self.ida_register_name_input)

        load_ida_button = UIHelpers.button(
            "Load Natives from IDA", self.load_natives_from_ida)
        load_ida_button.setToolTip(
            "Scan IDA Pro for native functions using the specified RegisterNative function")
        load_ida_layout.addWidget(load_ida_button)

        layout.addLayout(load_ida_layout)

        self.ida_load_status = QLabel("")
        layout.addWidget(self.ida_load_status)

        layout.addWidget(UIHelpers.separator())

        find_reg_label = UIHelpers.section_label(
            "<b>Find RegisterNative Function:</b>")
        find_reg_label.setToolTip(
            "Find the function that registers native functions in the IDA")
        layout.addWidget(find_reg_label)

        find_reg_layout = QHBoxLayout()
        find_reg_layout.addWidget(QLabel("Function Name:"))
        self.find_reg_name_input = QLineEdit()
        self.find_reg_name_input.setText(str(self.register_native_name))
        find_reg_layout.addWidget(self.find_reg_name_input)

        find_reg_button = UIHelpers.button(
            "Find RegisterNative", self.find_register_native)
        find_reg_layout.addWidget(find_reg_button)

        layout.addLayout(find_reg_layout)

        sig_layout = QHBoxLayout()
        sig_layout.addWidget(QLabel("Signature:"))
        self.reg_signature_input = QLineEdit(
            "4C 8B 05 ? ? ? ? 4C 8B C9 49 F7 D1")
        self.reg_signature_input.setToolTip(
            "Assembly signature pattern to search for in the IDA")
        sig_layout.addWidget(self.reg_signature_input)

        sig_search_button = UIHelpers.button(
            "Search by Signature", self.search_by_signature)
        sig_layout.addWidget(sig_search_button)

        layout.addLayout(sig_layout)

        self.find_reg_result = QLabel("Result will be shown here")
        layout.addWidget(self.find_reg_result)

        layout.addWidget(UIHelpers.separator())

        build_label = UIHelpers.section_label("<b>Find Game Build:</b>")
        build_label.setToolTip(
            "Find the game build version string in the executable")
        layout.addWidget(build_label)

        build_layout = QHBoxLayout()
        build_search_button = UIHelpers.button(
            "Find Game Build", self.find_game_build)
        build_layout.addWidget(build_search_button)

        layout.addLayout(build_layout)

        self.build_result = QLabel("Game build will be shown here")
        layout.addWidget(self.build_result)

        layout.addWidget(UIHelpers.separator())

        natives_json_label = UIHelpers.section_label(
            "<b>RDR3natives.json Operations:</b>")
        natives_json_label.setToolTip(
            "Work with RDR3natives.json file to get native names and namespaces")
        layout.addWidget(natives_json_label)

        natives_json_layout = QHBoxLayout()

        load_natives_json_button = UIHelpers.button(
            "Reload Native Names", lambda: None)
        load_natives_json_button.setToolTip(
            "Reload native names from local RDR3natives.json file")
        natives_json_layout.addWidget(load_natives_json_button)

        layout.addLayout(natives_json_layout)

        self.natives_json_status = QLabel("")
        layout.addWidget(self.natives_json_status)

        layout.addStretch(1)

    def _setup_misc_tab(self):
        misc_tab = QWidget()
        layout = QVBoxLayout(misc_tab)
        self.tab_widget.addTab(misc_tab, "Misc")
        layout.addWidget(QLabel("<b>Credits & Information:</b>"))
        credits_text = QLabel(
            "RDR2 Native Viewer - IDA Pro plugin for RDR2 native functions. Features: Load from IDA Pro, SQLite database, Advanced filtering, Native name resolution, RegisterNative discovery. Data: VORPCORE/RDR3natives.")
        credits_text.setMaximumHeight(200)
        credits_text.setWordWrap(True)
        layout.addWidget(credits_text)
        layout.addWidget(UIHelpers.separator())
        layout.addWidget(QLabel("<b>Community & Support:</b>"))
        discord_layout = QHBoxLayout()
        discord_layout.addWidget(QLabel("Join our Discord community:"))
        discord_button = UIHelpers.button(
            "Join Discord Server", self.copy_discord_invite)
        discord_layout.addWidget(discord_button)
        layout.addLayout(discord_layout)
        discord_info = QLabel("Discord Invite: S4pRcx5Sua")
        discord_info.setStyleSheet("color: #5865F2; font-weight: bold;")
        layout.addWidget(discord_info)
        layout.addStretch(1)

    def copy_discord_invite(self):
        discord_invite = "S4pRcx5Sua"
        full_invite = f"https://discord.gg/{discord_invite}"
        self.clipboard.setText(full_invite)
        self.show_status_message(
            f"Discord invite copied to clipboard: {full_invite}")

    def prompt_load_natives(self):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Load Natives")
        msg_box.setText("Would you like to load natives?")
        ida_button = msg_box.addButton(
            "Load from IDA", QMessageBox.ButtonRole.ActionRole)
        db_button = msg_box.addButton(
            "Load from Database", QMessageBox.ButtonRole.ActionRole)
        msg_box.addButton("Continue", QMessageBox.ButtonRole.RejectRole)
        msg_box.exec()
        clicked_button = msg_box.clickedButton()
        if clicked_button == ida_button:
            self.load_natives_from_ida()
        elif clicked_button == db_button:
            self.DB.load_natives_from_db()

    def load_natives_from_ida(self):
        self.natives_table.setRowCount(0)
        self.natives = []
        self.show_status_message("Loading natives from IDA...")
        if hasattr(self, 'ida_load_status'):
            self.ida_load_status.setText("Loading natives from IDA...")
            self.ida_load_status.setStyleSheet("color: blue")

        try:
            if hasattr(self, 'ida_register_name_input'):
                register_func_name = self.ida_register_name_input.text().strip()
            else:
                register_func_name = self.register_native_name_input.text().strip()

            if not register_func_name:
                register_func_name = DEFAULT_REGISTER_NATIVE_NAME

            try:
                raw_natives = get_all_natives_from_ida(
                    register_native_name=register_func_name)
            except Exception as e:
                print(f"Error in get_all_natives_from_ida: {str(e)}")
                error_msg = f"Failed to load natives: {str(e)}"
                self.show_status_message(error_msg, error=True)
                if hasattr(self, 'ida_load_status'):
                    self.ida_load_status.setText(error_msg)
                    self.ida_load_status.setStyleSheet("color: red")
                return

            if not raw_natives:
                error_msg = f"No native functions found using '{register_func_name}'. Check IDA console for details."
                self.show_status_message(error_msg, error=True)
                if hasattr(self, 'ida_load_status'):
                    self.ida_load_status.setText(error_msg)
                    self.ida_load_status.setStyleSheet("color: red")
                return

            for hash_val, func_addr, func_name in raw_natives:
                hash_str = f"{hash_val:016X}"

                native_name = ""
                namespace = ""
                if hash_str in self.native_names_map:
                    native_name = self.native_names_map[hash_str].get(
                        'name', '')
                    namespace = self.native_names_map[hash_str].get(
                        'namespace', '')

                native_entry: Dict[str, Any] = {
                    'hash': hash_val,
                    'hex_hash': f"0x{hash_val:016X}",
                    'addr': func_addr,
                    'hex_addr': f"0x{func_addr:X}",
                    'name': func_name,
                    'native_name': native_name,
                    'namespace': namespace
                }

                native_entry['search_string'] = (
                    native_entry['hex_hash'].lower() + ' ' +
                    native_entry['hex_addr'].lower() + ' ' +
                    native_entry['name'].lower() + ' ' +
                    native_entry['native_name'].lower() + ' ' +
                    native_entry['namespace'].lower()
                )

                self.natives.append(native_entry)

            self.update_table()

            self.data_source_label.setText("Data Source: IDA")
            self.data_source_label.setStyleSheet(
                "font-weight: bold; color: blue;")

            self.search_box.setPlaceholderText(
                f"Search {len(self.natives)} loaded natives...")

            success_msg = f"Successfully loaded {len(self.natives)} native functions."
            self.show_status_message(success_msg)

            if hasattr(self, 'ida_load_status'):
                self.ida_load_status.setText(success_msg)
                self.ida_load_status.setStyleSheet("color: green")

        except Exception as e:
            print(f"Error loading natives: {str(e)}")
            error_msg = f"Error loading natives: {str(e)}"
            self.show_status_message(error_msg, error=True)
            if hasattr(self, 'ida_load_status'):
                self.ida_load_status.setText(error_msg)
                self.ida_load_status.setStyleSheet("color: red")

    def show_status_message(self, message: str, error: bool = False) -> None:
        if error:
            self.status_bar.setStyleSheet("color: red; font-weight: bold;")
            QMessageBox.critical(
                self, "Error", message, QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton)
        else:
            self.status_bar.setStyleSheet("color: green;")
        self.status_bar.showMessage(message)

    def load_native_names(self):
        try:
            json_path = os.path.join(os.path.dirname(
                os.path.abspath(__file__)), DEFAULT_NATIVES_JSON)
            if not os.path.exists(json_path):
                print(f"RDR3natives.json not found at {json_path}")
                return
            with open(json_path, 'r') as f:
                native_data = json.load(f)
            self.native_names_map = {}
            for namespace, natives in native_data.items():
                for hash_str, native_info in natives.items():
                    if hash_str.startswith('0x'):
                        hash_str = hash_str[2:].upper()
                    else:
                        hash_str = hash_str.upper()
                    self.native_names_map[hash_str] = {
                        "name": native_info.get("name", ""), "namespace": namespace}
            print(
                f"Loaded {len(self.native_names_map)} native names and namespaces from {json_path}")
        except Exception as e:
            print(f"Error loading native names: {str(e)}")

    def update_table(self):
        self.natives_table.setRowCount(len(self.natives))
        self.natives_table.setSortingEnabled(False)
        for native in self.natives:
            if 'search_string' not in native:
                native['search_string'] = (
                    native.get('hex_hash', '').lower() + ' ' +
                    native.get('hex_addr', '').lower() + ' ' +
                    native.get('name', '').lower() + ' ' +
                    native.get('native_name', '').lower() + ' ' +
                    native.get('namespace', '').lower()
                )
        for row, native in enumerate(self.natives):
            self.insert_native_table_row(row, native)
        self.natives_table.setSortingEnabled(True)

    def insert_native_table_row(self, row: int, native: Dict[str, Any]) -> None:
        hex_hash = native.get('hex_hash', '')
        hex_addr = native.get('hex_addr', '')
        name = native.get('name', '')
        native_name = native.get('native_name', '')
        namespace = native.get('namespace', '')

        self.natives_table.setItem(row, 0, QTableWidgetItem(hex_hash))
        self.natives_table.setItem(row, 1, QTableWidgetItem(hex_addr))
        self.natives_table.setItem(row, 2, QTableWidgetItem(name))
        self.natives_table.setItem(row, 3, QTableWidgetItem(native_name))
        self.natives_table.setItem(row, 4, QTableWidgetItem(namespace))
        view_button = QPushButton("View Function")
        view_button.setToolTip(f"View function at {hex_addr} in IDA Pro")
        view_button.clicked.connect(
            lambda checked=False, addr=native['addr']: self.view_function(int(addr)))
        self.natives_table.setCellWidget(row, 5, view_button)

    def _start_filter_timer(self):
        self.filter_timer.stop()
        self.filter_timer.start(300)

    def filter_table(self):
        search_text = self.search_box.text().lower()
        if not search_text:
            for row in range(self.natives_table.rowCount()):
                self.natives_table.setRowHidden(row, False)
            self.lastFilteredNatives = self.natives
            self.lastSearchText = search_text
            return

        filter_hash = self.filter_hash_cb.isChecked()
        filter_addr = self.filter_addr_cb.isChecked()
        filter_name = self.filter_name_cb.isChecked()
        filter_native_name = self.filter_native_name_cb.isChecked()
        filter_namespace = self.filter_namespace_cb.isChecked()

        if not any([filter_hash, filter_addr, filter_name, filter_native_name, filter_namespace]):
            for row in range(self.natives_table.rowCount()):
                self.natives_table.setRowHidden(row, True)
            self.lastFilteredNatives = []
            self.lastSearchText = search_text
            return

        visible_count = 0
        filtered_natives: List[Dict[str, Any]] = []

        for row in range(self.natives_table.rowCount()):
            if row < len(self.natives):
                native = self.natives[row]
                matches = False

                if filter_hash and search_text in native.get('hex_hash', '').lower():
                    matches = True
                elif filter_addr and search_text in native.get('hex_addr', '').lower():
                    matches = True
                elif filter_name and search_text in native.get('name', '').lower():
                    matches = True
                elif filter_native_name and search_text in native.get('native_name', '').lower():
                    matches = True
                elif filter_namespace and search_text in native.get('namespace', '').lower():
                    matches = True

                if matches:
                    self.natives_table.setRowHidden(row, False)
                    filtered_natives.append(native)
                    visible_count += 1
                else:
                    self.natives_table.setRowHidden(row, True)
            else:
                self.natives_table.setRowHidden(row, True)

        self.lastFilteredNatives = filtered_natives
        self.lastSearchText = search_text

    def save_settings(self):
        try:
            new_register_native_name = self.register_native_name_input.text().strip()

            try:
                new_hash_offset = int(self.hash_offset_input.text(), 0)
                new_lea_offset = int(self.lea_offset_input.text(), 0)
            except ValueError:
                QMessageBox.warning(
                    self,
                    "Invalid Input",
                    "Offset values must be valid hexadecimal numbers (e.g., 0x8)",
                    QMessageBox.StandardButton.Ok,
                    QMessageBox.StandardButton.NoButton
                )
                return

            self.register_native_name = new_register_native_name
            self.offset_to_hash = new_hash_offset
            self.offset_to_lea = new_lea_offset

            self.settings.setValue(
                "register_native_name", self.register_native_name)

            self.settings.setValue("offset_to_hash", self.offset_to_hash)
            self.settings.setValue("offset_to_lea", self.offset_to_lea)

            self.settings.sync()

            self.settings_status_label.setText(
                "Settings saved successfully! Refresh to apply.")
            self.settings_status_label.setStyleSheet("color: green")

            QTimer.singleShot(
                3000, lambda: self.settings_status_label.setText(""))

        except Exception as e:
            UIHelpers.error(self, "Error",
                            f"An error occurred while saving settings: {str(e)}")

    def load_settings(self):
        try:
            self.register_native_name = self.settings.value(
                "register_native_name", DEFAULT_REGISTER_NATIVE_NAME, type=str)
            try:
                self.offset_to_hash = self.settings.value(
                    "offset_to_hash", OFFSET_TO_HASH, type=int)
                self.offset_to_lea = self.settings.value(
                    "offset_to_lea", OFFSET_TO_LEA, type=int)
            except (TypeError, ValueError):
                self.offset_to_hash = OFFSET_TO_HASH
                self.offset_to_lea = OFFSET_TO_LEA
        except Exception as e:
            print(f"Error loading settings: {e}")
            self.register_native_name = DEFAULT_REGISTER_NATIVE_NAME
            self.offset_to_hash = OFFSET_TO_HASH
            self.offset_to_lea = OFFSET_TO_LEA

    def reset_settings(self):
        try:
            reply_yes = UIHelpers.ask_yes_no(
                self,
                "Reset Settings",
                "Are you sure you want to reset all settings to default values?",
                default_yes=False,
            )

            if reply_yes:
                self.register_native_name = DEFAULT_REGISTER_NATIVE_NAME
                self.offset_to_hash = OFFSET_TO_HASH
                self.offset_to_lea = OFFSET_TO_LEA

                self.register_native_name_input.setText(
                    self.register_native_name)
                self.hash_offset_input.setText(f"0x{self.offset_to_hash:X}")
                self.lea_offset_input.setText(f"0x{self.offset_to_lea:X}")

                self.settings.clear()
                self.settings.sync()

                self.settings_status_label.setText(
                    "Settings reset to defaults!")
                self.settings_status_label.setStyleSheet("color: blue")

                QTimer.singleShot(
                    3000, lambda: self.settings_status_label.setText(""))

        except Exception as e:
            UIHelpers.error(self, "Error",
                            f"An error occurred while resetting settings: {str(e)}")

    def export_settings(self):
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Settings",
                os.path.expanduser("~/RDR2_NativeViewer_Settings.json"),
                "JSON Files (*.json)"
            )

            if not file_path:
                return

            settings_dict: Dict[str, Any] = {
                "register_native_name": self.register_native_name,
                "offset_to_hash": self.offset_to_hash,
                "offset_to_lea": self.offset_to_lea,
            }

            with open(file_path, 'w') as f:
                json.dump(settings_dict, f, indent=4)

            self.settings_status_label.setText(
                f"Settings exported to {os.path.basename(file_path)}")
            self.settings_status_label.setStyleSheet("color: green")

            QTimer.singleShot(
                3000, lambda: self.settings_status_label.setText(""))

        except Exception as e:
            UIHelpers.error(self, "Error",
                            f"An error occurred while exporting settings: {str(e)}")

    def import_settings(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Import Settings",
                os.path.expanduser("~"),
                "JSON Files (*.json)"
            )

            if not file_path:
                return

            with open(file_path, 'r') as f:
                settings_dict = json.load(f)

            required_keys = ["register_native_name",
                             "offset_to_hash", "offset_to_lea"]
            for key in required_keys:
                if key not in settings_dict:
                    UIHelpers.warn(self, "Invalid Settings File",
                                   f"The settings file is missing the '{key}' setting.")
                    return

            self.register_native_name = settings_dict["register_native_name"]
            self.offset_to_hash = int(settings_dict["offset_to_hash"])
            self.offset_to_lea = int(settings_dict["offset_to_lea"])

            self.register_native_name_input.setText(self.register_native_name)

            self.hash_offset_input.setText(f"0x{self.offset_to_hash:X}")
            self.lea_offset_input.setText(f"0x{self.offset_to_lea:X}")

            self.settings.setValue(
                "register_native_name", self.register_native_name)
            self.settings.setValue("offset_to_hash", self.offset_to_hash)
            self.settings.setValue("offset_to_lea", self.offset_to_lea)

            self.settings.sync()

            self.settings_status_label.setText(
                f"Settings imported from {os.path.basename(file_path)}")
            self.settings_status_label.setStyleSheet("color: green")

            QTimer.singleShot(
                3000, lambda: self.settings_status_label.setText(""))

        except json.JSONDecodeError:
            UIHelpers.error(
                self, "Error", "The selected file is not a valid JSON file.")
        except Exception as e:
            UIHelpers.error(self, "Error",
                            f"An error occurred while importing settings: {str(e)}")

    def view_function(self, addr: int) -> None:
        try:
            try:
                import importlib
                ida_kernwin = importlib.import_module('ida_kernwin')
                ida_kernwin.jumpto(addr)
            except (ImportError, ModuleNotFoundError):
                UIHelpers.info(self, "View Function",
                               f"Viewing function at {hex(addr)} (In IDA Pro this would jump to the function)")
        except Exception as e:
            UIHelpers.error(
                self, "Error", f"An error occurred while trying to view the function: {str(e)}")

    def show_context_menu(self, position: Any) -> None:
        row = self.natives_table.rowAt(position.y())
        if row < 0:
            return
        context_menu = QMenu(self)
        copy_hash_action = context_menu.addAction("Copy Hash")
        copy_addr_action = context_menu.addAction("Copy Address")
        copy_func_name_action = context_menu.addAction("Copy Function Name")
        copy_native_name_action = context_menu.addAction("Copy Native Name")
        copy_native_namespace_action = context_menu.addAction(
            "Copy Native Namespace")
        copy_all_action = context_menu.addAction("Copy All Data")
        action = context_menu.exec(QCursor.pos())
        if not action:
            return

        hash_item = self.natives_table.item(row, 0)
        addr_item = self.natives_table.item(row, 1)
        func_name_item = self.natives_table.item(row, 2)
        native_name_item = self.natives_table.item(row, 3)
        native_namespace_item = self.natives_table.item(row, 4)

        hash_value = hash_item.text() if hash_item else ""
        addr = addr_item.text() if addr_item else ""
        func_name = func_name_item.text() if func_name_item else ""
        native_name = native_name_item.text() if native_name_item else ""
        native_namespace = native_namespace_item.text() if native_namespace_item else ""

        if action == copy_hash_action and hash_value:

            self.clipboard.setText(hash_value)
            self.show_status_message(f"Copied hash: {hash_value}")

        elif action == copy_addr_action and addr:
            self.clipboard.setText(addr)
            self.show_status_message(f"Copied address: {addr}")

        elif action == copy_func_name_action and func_name:
            self.clipboard.setText(func_name)
            self.show_status_message(f"Copied function name: {func_name}")

        elif action == copy_native_name_action:
            if native_name:
                self.clipboard.setText(native_name)
                self.show_status_message(f"Copied native name: {native_name}")
            else:
                self.show_status_message("Native name is empty", error=True)

        elif action == copy_native_namespace_action:
            if native_namespace:
                self.clipboard.setText(native_namespace)
                self.show_status_message(
                    f"Copied native namespace: {native_namespace}")
            else:
                self.show_status_message(
                    "Native namespace is empty", error=True)

        elif action == copy_all_action:
            all_data = f"Hash: {hash_value}\nAddress: {addr}\nFunction Name: {func_name}\nNative Name: {native_name or '<None>'}\nNative Namespace: {native_namespace or '<None>'}"
            self.clipboard.setText(all_data)
            self.show_status_message("Copied all native data")

    def refresh_natives(self):
        if self.current_db_path:
            self.DB.load_natives_from_db()
        else:
            self.show_status_message("No database loaded to refresh")

    def find_register_native(self):
        try:
            reg_name = self.find_reg_name_input.text().strip()
            if not reg_name:
                reg_name = DEFAULT_REGISTER_NATIVE_NAME
                self.find_reg_name_input.setText(reg_name)

            try:
                reg_address = FindRegisterNative()
            except ValueError as e:
                self.find_reg_result.setText(
                    f"Error: {str(e)}")
                self.find_reg_result.setStyleSheet("color: red;")
                return
            except Exception as e:
                self.find_reg_result.setText(
                    f"Unexpected error: {str(e)}")
                self.find_reg_result.setStyleSheet("color: red;")
                return

            if reg_address is not None:
                if isinstance(reg_address, list):
                    if len(reg_address) > 0:
                        address_to_use = reg_address[0]
                        address_text = f"{hex(address_to_use)} (+ {len(reg_address)-1} more)"
                    else:
                        self.find_reg_result.setText(
                            "No valid addresses found.")
                        self.find_reg_result.setStyleSheet("color: red;")
                        return
                else:
                    address_to_use = reg_address
                    address_text = hex(address_to_use)

                self.find_reg_result.setText(
                    f"RegisterNative function found at: {address_text}")
                self.find_reg_result.setStyleSheet(
                    "color: green; font-weight: bold;")

                reply_yes = UIHelpers.ask_yes_no(
                    self,
                    "Function Found",
                    f"RegisterNative function found at {address_text}.\nDo you want to update your settings with this function name?",
                    default_yes=True,
                )

                if reply_yes:
                    self.register_native_name = reg_name
                    self.register_native_name_input.setText(reg_name)
                    self.settings.setValue("register_native_name", reg_name)
                    self.settings.sync()
                    self.settings_status_label.setText(
                        f"Settings updated with function name: {reg_name}")
                    self.settings_status_label.setStyleSheet("color: green")
                    QTimer.singleShot(
                        3000, lambda: self.settings_status_label.setText(""))
                try:
                    import importlib
                    ida_kernwin = importlib.import_module('ida_kernwin')
                    ida_kernwin.jumpto(address_to_use)
                except (ImportError, ModuleNotFoundError):
                    pass
            else:
                self.find_reg_result.setText(
                    "Could not find RegisterNative function. Check IDA console for details.")
                self.find_reg_result.setStyleSheet("color: red;")

        except Exception as e:
            self.find_reg_result.setText(f"Error: {str(e)}")
            self.find_reg_result.setStyleSheet("color: red;")

    def search_by_signature(self):
        try:
            signature = self.reg_signature_input.text().strip()
            if not signature:
                self.find_reg_result.setText("Error: No signature provided")
                self.find_reg_result.setStyleSheet("color: red;")
                return
            try:
                reg_address = FindRegisterNative(signature)
            except Exception as e:
                self.find_reg_result.setText(f"Error during search: {str(e)}")
                self.find_reg_result.setStyleSheet("color: red;")
                return
            if reg_address is not None:
                if isinstance(reg_address, list):
                    if len(reg_address) > 0:
                        address_to_use = reg_address[0]
                        address_text = f"{hex(address_to_use)} (+ {len(reg_address)-1} more matches)"
                    else:
                        self.find_reg_result.setText(
                            "No matches found for signature")
                        self.find_reg_result.setStyleSheet("color: red;")
                        return
                else:
                    address_to_use = reg_address
                    address_text = hex(address_to_use)

                self.find_reg_result.setText(
                    f"Found address using signature: {address_text}")
                self.find_reg_result.setStyleSheet(
                    "color: green; font-weight: bold;")

                reply_yes = UIHelpers.ask_yes_no(
                    self,
                    "Function Found",
                    f"RegisterNative function found at {address_text}.\nDo you want to view this function?",
                    default_yes=True,
                )

                if reply_yes:
                    try:
                        import importlib
                        ida_kernwin = importlib.import_module('ida_kernwin')
                        ida_kernwin.jumpto(address_to_use)
                    except (ImportError, ModuleNotFoundError):
                        UIHelpers.info(
                            self, "View Function", f"Would jump to function at {address_text} in IDA Pro")
            else:
                self.find_reg_result.setText(
                    "No matches found for the signature")
                self.find_reg_result.setStyleSheet("color: red;")

        except Exception as e:
            self.find_reg_result.setText(f"Error: {str(e)}")
            self.find_reg_result.setStyleSheet("color: red;")

    def find_game_build(self):
        try:
            build = FindGameBuild()
            if build:
                if isinstance(build, list):
                    build_text = ", ".join(str(b) for b in build)
                    self.build_result.setText(
                        f"Multiple game builds found: {build_text}")
                else:
                    self.build_result.setText(f"Game Build: {build}")
                self.build_result.setStyleSheet(
                    "color: green; font-weight: bold;")
            else:
                self.build_result.setText("Could not find game build")
                self.build_result.setStyleSheet("color: red;")
        except Exception as e:
            self.build_result.setText(f"Error finding game build: {str(e)}")
            self.build_result.setStyleSheet("color: red;")


class NV_DB():
    def __init__(self, parent: 'NativeViewerUI'):
        self.parent: 'NativeViewerUI' = parent

    def browse_db_file(self) -> Optional[str]:
        try:
            if not self.parent:
                print("Error: Parent UI reference is None")
                return None

            default_path = str(self.parent.settings.value(
                "last_db_path", os.path.expanduser("~/RDR2_Natives.db")))

            file_path, _ = QFileDialog.getSaveFileName(
                self.parent,
                "Select SQLite Database File",
                default_path,
                "SQLite Database (*.db);;All Files (*)"
            )

            if file_path:
                self.parent.db_file_path.setText(file_path)

                self.parent.settings.setValue("last_db_path", file_path)

                return file_path

            return None

        except Exception as e:
            print(
                f"Error in browse_db_file: {str(e)}")
            if self.parent:
                self.parent.show_status_message(
                    f"Error selecting database file: {str(e)}", error=True)
            return None

    def save_natives_to_db(self, natives: List[Dict[str, Any]], db_path: Optional[str] = None, register_native_name: Optional[str] = None) -> bool:
        conn = None
        try:
            if not natives:
                if self.parent:
                    UIHelpers.warn(self.parent, "No Data",
                                   "No native functions to save. Please load natives first.")
                return False

            if db_path is None and self.parent:
                db_path = self.parent.db_file_path.text().strip()

            if not db_path:
                if self.parent:
                    UIHelpers.warn(self.parent, "No Database File",
                                   "Please specify a database file path.")
                return False

            db_path = str(db_path)

            if os.path.exists(db_path) and self.parent:
                overwrite = UIHelpers.ask_yes_no(
                    self.parent,
                    "File Exists",
                    f"The file {os.path.basename(db_path)} already exists. Do you want to overwrite it?",
                    default_yes=False,
                )
                if not overwrite:
                    return False
            progress = None
            if self.parent:
                progress = UIHelpers.progress(
                    self.parent, "Saving to Database", "Saving natives to database...", len(natives))
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
            CREATE TABLE IF NOT EXISTS natives (
                hash TEXT PRIMARY KEY,
                address TEXT,
                name TEXT,
                native_name TEXT,
                namespace TEXT,
                timestamp TEXT
            )
            ''')

            cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            ''')

            conn.isolation_level = None  # Control transactions manually
            conn.execute("BEGIN")

            timestamp = datetime.datetime.now().isoformat()
            cursor.execute("INSERT OR REPLACE INTO metadata VALUES (?, ?)",
                           ("timestamp", timestamp))
            cursor.execute("INSERT OR REPLACE INTO metadata VALUES (?, ?)",
                           ("source", "RDR2 Native Viewer"))

            if register_native_name is None and self.parent:
                register_native_name = str(self.parent.register_native_name)

            if register_native_name:
                cursor.execute("INSERT OR REPLACE INTO metadata VALUES (?, ?)",
                               ("register_native_name", register_native_name))

            for i, native in enumerate(natives):
                if progress and progress.wasCanceled():
                    conn.rollback()
                    conn.close()
                    if self.parent:
                        self.parent.show_status_message("Operation cancelled")
                    return False

                cursor.execute(
                    "INSERT OR REPLACE INTO natives VALUES (?, ?, ?, ?, ?, ?)",
                    (native['hex_hash'], native['hex_addr'],
                     native['name'], native.get('native_name', ''),
                     native.get('namespace', ''), timestamp)
                )

                if progress:
                    progress.setValue(i + 1)

            conn.commit()
            conn.close()

            if self.parent:
                db_filename = os.path.basename(db_path)

                self.parent.show_status_message(
                    f"Successfully saved {len(natives)} natives to {db_filename}")

                self.parent.settings.setValue("last_db_path", db_path)

            return True

        except sqlite3.Error as e:
            try:
                if conn is not None:
                    conn.rollback()
                    conn.close()
            except:
                pass  # Connection might already be closed

            if self.parent:
                UIHelpers.error(self.parent, "Database Error",
                                f"A database error occurred: {str(e)}")
                self.parent.show_status_message(f"Error: {str(e)}")

            print(f"Database error: {str(e)}")

            return False

        except Exception as e:
            if self.parent:
                UIHelpers.error(self.parent, "Error",
                                f"An error occurred: {str(e)}")
                self.parent.show_status_message(f"Error: {str(e)}")

            return False

    def load_natives_from_db(self, db_path: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
        conn = None
        try:
            if db_path is None and self.parent:
                db_path = self.parent.db_file_path.text().strip()
                if not db_path:
                    db_path = str(
                        self.parent.settings.value("last_db_path", ""))
                    if db_path:
                        self.parent.db_file_path.setText(db_path)
                    else:
                        if self.parent:
                            UIHelpers.warn(self.parent, "No Database File",
                                           "Please specify a database file path.")
                        return None
            if not db_path:
                print("Error: No database path provided")
                return None
            if not os.path.exists(db_path):
                if self.parent:
                    UIHelpers.warn(self.parent, "File Not Found",
                                   f"The database file {db_path} does not exist.")
                return None

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='natives'")
            if not cursor.fetchone():
                if self.parent:
                    UIHelpers.warn(self.parent, "Invalid Database",
                                   "This database does not contain a natives table.")
                conn.close()
                return None

            metadata_str = "No metadata available"
            try:
                cursor.execute("SELECT key, value FROM metadata")
                metadata = dict(cursor.fetchall())
                metadata_str = "\n".join(
                    [f"{k}: {v}" for k, v in metadata.items()])
            except sqlite3.Error:
                metadata_str = "No metadata available"
            if self.parent:
                db_filename = os.path.basename(str(db_path))
                proceed = UIHelpers.ask_yes_no(
                    self.parent, "Load Natives", f"Load natives from {db_filename}?\n\nDatabase Information:\n{metadata_str}", default_yes=True)
                if not proceed:
                    conn.close()
                    return None

            cursor.execute("SELECT COUNT(*) FROM natives")
            total_natives = cursor.fetchone()[0]
            progress = None
            if self.parent:
                progress = UIHelpers.progress(
                    self.parent, "Loading from Database", "Loading natives from database...", total_natives)
            cursor.execute("PRAGMA table_info(natives)")
            columns = {column_info[1] for column_info in cursor.fetchall()}
            natives: List[Dict[str, Any]] = []
            has_extended_schema = 'native_name' in columns and 'namespace' in columns
            if has_extended_schema:
                query = "SELECT hash, address, name, native_name, namespace FROM natives"
            else:
                query = "SELECT hash, address, name FROM natives"
            cursor.execute(query)

            for i, row in enumerate(cursor.fetchall()):
                if progress and progress.wasCanceled():
                    conn.close()
                    if self.parent:
                        self.parent.show_status_message("Operation cancelled")
                    return None
                if has_extended_schema:
                    hash_val, addr, name, native_name, namespace = row
                else:
                    hash_val, addr, name = row
                    native_name = ""
                    namespace = ""
                int_hash = int(hash_val, 16) if hash_val.startswith(
                    '0x') else int(hash_val)
                int_addr = int(addr, 16) if addr.startswith(
                    '0x') else int(addr)

                native_entry: Dict[str, Any] = {
                    'hash': int_hash,
                    'hex_hash': hash_val,
                    'addr': int_addr,
                    'hex_addr': addr,
                    'name': name,
                    'native_name': native_name,
                    'namespace': namespace
                }
                native_entry['search_string'] = (
                    native_entry['hex_hash'].lower() + ' ' +
                    native_entry['hex_addr'].lower() + ' ' +
                    native_entry['name'].lower() + ' ' +
                    native_entry['native_name'].lower() + ' ' +
                    native_entry['namespace'].lower()
                )
                natives.append(native_entry)
                if progress:
                    progress.setValue(i + 1)

            conn.close()
            if self.parent:
                db_filename = os.path.basename(str(db_path))
                self.parent.natives = natives
                self.parent.update_table()
                self.parent.data_source_label.setText(
                    f"Data Source: SQLite Database ({db_filename})")
                self.parent.data_source_label.setStyleSheet(
                    "font-weight: bold; color: green;")
                self.parent.show_status_message(
                    f"Successfully loaded {len(natives)} natives from {db_filename}")
                self.parent.search_box.setPlaceholderText(
                    f"Search {len(natives)} loaded natives...")
                self.parent.current_db_path = str(db_path)
            return natives

        except sqlite3.Error as e:
            try:
                if conn is not None:
                    conn.close()
            except:
                pass
            if self.parent:
                UIHelpers.error(self.parent, "Database Error",
                                f"A database error occurred: {str(e)}")
                self.parent.show_status_message(f"Error: {str(e)}")
            print(f"Database error: {str(e)}")
            return None
        except Exception as e:
            if self.parent:
                UIHelpers.error(self.parent, "Error",
                                f"An error occurred: {str(e)}")
                self.parent.show_status_message(f"Error: {str(e)}")
            return None


def run():
    global _native_viewer_window
    print("RDR2 Native Viewer")
    print("------------------")
    try:
        app = QApplication.instance() or QApplication([])
        if isinstance(app, QApplication):
            window = NativeViewerUI(app.clipboard())
            window.show()
            window.activateWindow()
            window.raise_()
            app.exec()
            _native_viewer_window = window
            return window
        else:
            print("Error: Could not get QApplication instance")
            return None
    except Exception as e:
        print(f"Error running UI: {str(e)}")
        return None


if __name__ == "__main__":
    run()
