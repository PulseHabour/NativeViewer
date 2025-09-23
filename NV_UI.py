
from typing import Optional, List, Dict, Any
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

# GitHub repository information
GITHUB_REPO_OWNER = "VORPCORE"
GITHUB_REPO_NAME = "RDR3natives"
GITHUB_FILE_PATH = "rdr3natives.json"
GITHUB_BRANCH = "main"


WINDOW_WIDTH = 1000
WINDOW_HEIGHT = 700


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

        # Add filter checkboxes
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

        # Add both layouts to a vertical layout
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

        func_location_label = QLabel("<b>Function Location Settings:</b>")
        layout.addWidget(func_location_label)

        reg_name_layout = QHBoxLayout()
        reg_name_layout.addWidget(QLabel("RegisterNative Function Name:"))
        self.register_native_name_input = QLineEdit()
        self.register_native_name_input.setText(str(self.register_native_name))
        self.register_native_name_input.setToolTip(
            "Name of the function that registers native functions")
        reg_name_layout.addWidget(self.register_native_name_input)
        layout.addLayout(reg_name_layout)

        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(separator)

        offset_label = QLabel("<b>Offset Settings:</b>")
        layout.addWidget(offset_label)

        hash_offset_layout = QHBoxLayout()
        hash_offset_layout.addWidget(QLabel("Offset to Hash:"))
        self.hash_offset_input = QLineEdit(f"0x{self.offset_to_hash:X}")
        self.hash_offset_input.setToolTip(
            "Byte offset to the hash value in the RegisterNative call")
        hash_offset_layout.addWidget(self.hash_offset_input)
        layout.addLayout(hash_offset_layout)

        lea_offset_layout = QHBoxLayout()
        lea_offset_layout.addWidget(QLabel("Offset to LEA:"))
        self.lea_offset_input = QLineEdit(f"0x{self.offset_to_lea:X}")
        self.lea_offset_input.setToolTip(
            "Byte offset to the LEA instruction in the RegisterNative call")
        lea_offset_layout.addWidget(self.lea_offset_input)
        layout.addLayout(lea_offset_layout)

        separator2 = QFrame()
        separator2.setFrameShape(QFrame.Shape.HLine)
        separator2.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(separator2)

        buttons_layout = QHBoxLayout()

        save_settings_button = QPushButton("Save Settings")
        save_settings_button.clicked.connect(self.save_settings)
        buttons_layout.addWidget(save_settings_button)

        reset_settings_button = QPushButton("Reset to Defaults")
        reset_settings_button.clicked.connect(self.reset_settings)
        buttons_layout.addWidget(reset_settings_button)

        layout.addLayout(buttons_layout)

        io_buttons_layout = QHBoxLayout()

        import_settings_button = QPushButton("Import Settings")
        import_settings_button.clicked.connect(self.import_settings)
        io_buttons_layout.addWidget(import_settings_button)

        layout.addLayout(io_buttons_layout)

        self.settings_status_label = QLabel("")
        layout.addWidget(self.settings_status_label)

        separator3 = QFrame()
        separator3.setFrameShape(QFrame.Shape.HLine)
        separator3.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(separator3)

        # SQLite Database section
        sqlite_label = QLabel("<b>SQLite Database Operations:</b>")
        sqlite_label.setToolTip(
            "Save and load native functions to/from a SQLite database")
        layout.addWidget(sqlite_label)

        # Save natives to database
        save_db_layout = QHBoxLayout()
        save_db_layout.addWidget(QLabel("Database File:"))
        self.db_file_path = QLineEdit()
        self.db_file_path.setPlaceholderText("Path to SQLite database file")
        save_db_layout.addWidget(self.db_file_path)

        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.DB.browse_db_file)
        save_db_layout.addWidget(browse_button)

        layout.addLayout(save_db_layout)

        # Buttons for database operations
        db_buttons_layout = QHBoxLayout()

        save_natives_button = QPushButton("Save Natives to DB")
        save_natives_button.clicked.connect(
            lambda: self.DB.save_natives_to_db(self.natives))
        save_natives_button.setToolTip(
            "Save currently loaded native functions to the specified database file")
        db_buttons_layout.addWidget(save_natives_button)

        load_natives_button = QPushButton("Load Natives from DB")
        load_natives_button.clicked.connect(
            lambda: self.DB.load_natives_from_db())
        load_natives_button.setToolTip(
            "Load native functions from the specified database file")
        db_buttons_layout.addWidget(load_natives_button)

        layout.addLayout(db_buttons_layout)

        layout.addStretch(1)

    def _setup_tools_tab(self):

        tools_tab = QWidget()
        layout = QVBoxLayout(tools_tab)
        self.tab_widget.addTab(tools_tab, "Tools")

        # Load Natives from IDA section
        load_ida_label = QLabel("<b>Load Natives from IDA:</b>")
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

        load_ida_button = QPushButton("Load Natives from IDA")
        load_ida_button.clicked.connect(self.load_natives_from_ida)
        load_ida_button.setToolTip(
            "Scan IDA Pro for native functions using the specified RegisterNative function")
        load_ida_layout.addWidget(load_ida_button)

        layout.addLayout(load_ida_layout)

        # Status display for IDA loading
        self.ida_load_status = QLabel("")
        layout.addWidget(self.ida_load_status)

        # Separator
        separator_ida = QFrame()
        separator_ida.setFrameShape(QFrame.Shape.HLine)
        separator_ida.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(separator_ida)

        find_reg_label = QLabel("<b>Find RegisterNative Function:</b>")
        find_reg_label.setToolTip(
            "Find the function that registers native functions in the IDA")
        layout.addWidget(find_reg_label)

        find_reg_layout = QHBoxLayout()
        find_reg_layout.addWidget(QLabel("Function Name:"))
        self.find_reg_name_input = QLineEdit()
        self.find_reg_name_input.setText(str(self.register_native_name))
        find_reg_layout.addWidget(self.find_reg_name_input)

        find_reg_button = QPushButton("Find RegisterNative")
        find_reg_button.clicked.connect(self.find_register_native)
        find_reg_layout.addWidget(find_reg_button)

        layout.addLayout(find_reg_layout)

        # Signature search
        sig_layout = QHBoxLayout()
        sig_layout.addWidget(QLabel("Signature:"))
        self.reg_signature_input = QLineEdit(
            "4C 8B 05 ? ? ? ? 4C 8B C9 49 F7 D1")
        self.reg_signature_input.setToolTip(
            "Assembly signature pattern to search for in the IDA")
        sig_layout.addWidget(self.reg_signature_input)

        sig_search_button = QPushButton("Search by Signature")
        sig_search_button.clicked.connect(self.search_by_signature)
        sig_layout.addWidget(sig_search_button)

        layout.addLayout(sig_layout)

        # Result display
        self.find_reg_result = QLabel("Result will be shown here")
        layout.addWidget(self.find_reg_result)

        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(separator)

        # Game Build Search section
        build_label = QLabel("<b>Find Game Build:</b>")
        build_label.setToolTip(
            "Find the game build version string in the executable")
        layout.addWidget(build_label)

        build_layout = QHBoxLayout()
        build_search_button = QPushButton("Find Game Build")
        build_search_button.clicked.connect(self.find_game_build)
        build_layout.addWidget(build_search_button)

        layout.addLayout(build_layout)

        # Result display for game build
        self.build_result = QLabel("Game build will be shown here")
        layout.addWidget(self.build_result)

        # Separator
        separator2 = QFrame()
        separator2.setFrameShape(QFrame.Shape.HLine)
        separator2.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(separator2)

        # RDR3natives.json section
        natives_json_label = QLabel("<b>RDR3natives.json Operations:</b>")
        natives_json_label.setToolTip(
            "Work with RDR3natives.json file to get native names and namespaces")
        layout.addWidget(natives_json_label)

        # Load and update natives buttons
        natives_json_layout = QHBoxLayout()

        load_natives_json_button = QPushButton("Reload Native Names")
        load_natives_json_button.setToolTip(
            "Reload native names from local RDR3natives.json file")
        # load_natives_json_button.clicked.connect(self.reload_native_names)
        natives_json_layout.addWidget(load_natives_json_button)

        layout.addLayout(natives_json_layout)

        # Status display for RDR3natives.json operations
        self.natives_json_status = QLabel("")
        layout.addWidget(self.natives_json_status)

        # Add spacer to push everything to the top
        layout.addStretch(1)

    def prompt_load_natives(self):
        """Display a dialog asking user to choose data source."""
        # Create message box with proper constructor parameters
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Load Natives")
        msg_box.setText("Wwould you like to load natives?")

        # Add buttons with specific roles
        ida_button = msg_box.addButton(
            "Load from IDA", QMessageBox.ButtonRole.ActionRole)
        db_button = msg_box.addButton(
            "Load from Database", QMessageBox.ButtonRole.ActionRole)
        msg_box.addButton("Continue", QMessageBox.ButtonRole.RejectRole)

        # Show the dialog and get the result
        msg_box.exec()

        # Handle the clicked button
        clicked_button = msg_box.clickedButton()
        if clicked_button == ida_button:
            self.load_natives_from_ida()
        elif clicked_button == db_button:
            self.load_natives_from_db()

    def load_natives_from_ida(self):
        """Load natives from IDA."""

        # Clear existing data
        self.natives_table.setRowCount(0)
        self.natives = []

        # Show progress in status bar
        self.show_status_message("Loading natives from IDA...")

        # Update tools tab status
        if hasattr(self, 'ida_load_status'):
            self.ida_load_status.setText("Loading natives from IDA...")
            self.ida_load_status.setStyleSheet("color: blue")

        try:
            # Get register function name from the tools tab input if available, otherwise from settings
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

            # Check if we got any natives back
            if not raw_natives:
                error_msg = f"No native functions found using '{register_func_name}'. Check IDA console for details."
                self.show_status_message(error_msg, error=True)
                if hasattr(self, 'ida_load_status'):
                    self.ida_load_status.setText(error_msg)
                    self.ida_load_status.setStyleSheet("color: red")
                return

            # Process natives
            for hash_val, func_addr, func_name in raw_natives:
                # Create the hash string in the format used in the mapping
                hash_str = f"{hash_val:016X}"

                # Look up native name and namespace
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

                # Pre-compute search string for faster filtering
                native_entry['search_string'] = (
                    native_entry['hex_hash'].lower() + ' ' +
                    native_entry['hex_addr'].lower() + ' ' +
                    native_entry['name'].lower() + ' ' +
                    native_entry['native_name'].lower() + ' ' +
                    native_entry['namespace'].lower()
                )

                self.natives.append(native_entry)

            # Populate table
            self.update_table()

            # Update data source label
            self.data_source_label.setText("Data Source: IDA")
            self.data_source_label.setStyleSheet(
                "font-weight: bold; color: blue;")

            # Update search box placeholder
            self.search_box.setPlaceholderText(
                f"Search {len(self.natives)} loaded natives...")

            # Show success message
            success_msg = f"Successfully loaded {len(self.natives)} native functions."
            self.show_status_message(success_msg)

            # Update tools tab status
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

        # Show in status bar
        self.status_bar.showMessage(message)

    def load_native_names(self):
        """Load native names and namespaces from RDR3natives.json file."""
        try:
            json_path = os.path.join(os.path.dirname(
                os.path.abspath(__file__)), DEFAULT_NATIVES_JSON)
            if not os.path.exists(json_path):
                print(f"RDR3natives.json not found at {json_path}")
                return

            # Load the JSON file
            with open(json_path, 'r') as f:
                native_data = json.load(f)

            # Process the native data
            self.native_names_map = {}

            # Build map of hash to name and namespace
            for namespace, natives in native_data.items():
                for hash_str, native_info in natives.items():
                    # Remove the '0x' prefix if present and convert to uppercase
                    if hash_str.startswith('0x'):
                        hash_str = hash_str[2:].upper()
                    else:
                        hash_str = hash_str.upper()

                    # Store the native name and namespace
                    self.native_names_map[hash_str] = {
                        "name": native_info.get("name", ""),
                        "namespace": namespace
                    }

            print(
                f"Loaded {len(self.native_names_map)} native names and namespaces from {json_path}")

        except Exception as e:
            print(f"Error loading native names: {str(e)}")

    def update_table(self):
        """Update the table with the current natives.

        Populates the table with data from self.natives list, including hash values,
        addresses, function names, native names, and action buttons.
        """

        self.natives_table.setRowCount(len(self.natives))
        self.natives_table.setSortingEnabled(False)

        # Ensure all natives have search strings for performance
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
        """Start or restart the debounce timer for filtering.

        This method is called on every text change and restarts the timer
        to delay the actual filtering until the user stops typing.
        """

        self.filter_timer.stop()
        self.filter_timer.start(300)

    def filter_table(self):
        """Filter the table based on search text and selected filter checkboxes using row hiding for better performance."""
        search_text = self.search_box.text().lower()

        # If search is empty, show all rows
        if not search_text:
            for row in range(self.natives_table.rowCount()):
                self.natives_table.setRowHidden(row, False)
            self.lastFilteredNatives = self.natives
            self.lastSearchText = search_text
            return

        # Get checkbox states
        filter_hash = self.filter_hash_cb.isChecked()
        filter_addr = self.filter_addr_cb.isChecked()
        filter_name = self.filter_name_cb.isChecked()
        filter_native_name = self.filter_native_name_cb.isChecked()
        filter_namespace = self.filter_namespace_cb.isChecked()

        # If no checkboxes are selected, hide all rows
        if not any([filter_hash, filter_addr, filter_name, filter_native_name, filter_namespace]):
            for row in range(self.natives_table.rowCount()):
                self.natives_table.setRowHidden(row, True)
            self.lastFilteredNatives = []
            self.lastSearchText = search_text
            return

        # Hide/show rows based on search and checkbox selections
        visible_count = 0
        filtered_natives: List[Dict[str, Any]] = []

        for row in range(self.natives_table.rowCount()):
            if row < len(self.natives):
                native = self.natives[row]
                matches = False

                # Check each field only if its checkbox is selected
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
                # Hide any extra rows
                self.natives_table.setRowHidden(row, True)

        self.lastFilteredNatives = filtered_natives
        self.lastSearchText = search_text

    def save_settings(self):
        try:
            # Get values from inputs
            new_register_native_name = self.register_native_name_input.text().strip()

            # Parse hex values
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

            # Update settings
            self.register_native_name = new_register_native_name
            self.offset_to_hash = new_hash_offset
            self.offset_to_lea = new_lea_offset

            # Save to QSettings
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
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred while saving settings: {str(e)}",
                QMessageBox.StandardButton.Ok,
                QMessageBox.StandardButton.NoButton
            )

    def load_settings(self):
        try:
            # Load settings or use defaults
            self.register_native_name = self.settings.value(
                "register_native_name", DEFAULT_REGISTER_NATIVE_NAME, type=str)

            # Handle integer values with proper type conversion
            try:
                self.offset_to_hash = self.settings.value(
                    "offset_to_hash", OFFSET_TO_HASH, type=int)
                self.offset_to_lea = self.settings.value(
                    "offset_to_lea", OFFSET_TO_LEA, type=int)
            except (TypeError, ValueError):
                # Fall back to defaults if conversion fails
                self.offset_to_hash = OFFSET_TO_HASH
                self.offset_to_lea = OFFSET_TO_LEA
        except Exception as e:
            print(f"Error loading settings: {e}")
            # Fall back to defaults
            self.register_native_name = DEFAULT_REGISTER_NATIVE_NAME
            self.offset_to_hash = OFFSET_TO_HASH
            self.offset_to_lea = OFFSET_TO_LEA

    def reset_settings(self):
        try:
            # Ask for confirmation
            reply = QMessageBox.question(
                self,
                "Reset Settings",
                "Are you sure you want to reset all settings to default values?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                # Reset to defaults
                self.register_native_name = DEFAULT_REGISTER_NATIVE_NAME
                self.offset_to_hash = OFFSET_TO_HASH
                self.offset_to_lea = OFFSET_TO_LEA

                # Update UI
                self.register_native_name_input.setText(
                    self.register_native_name)
                self.hash_offset_input.setText(f"0x{self.offset_to_hash:X}")
                self.lea_offset_input.setText(f"0x{self.offset_to_lea:X}")

                # Clear QSettings
                self.settings.clear()
                self.settings.sync()

                # Show success message
                self.settings_status_label.setText(
                    "Settings reset to defaults!")
                self.settings_status_label.setStyleSheet("color: blue")

                # Clear the status message after 3 seconds

                QTimer.singleShot(
                    3000, lambda: self.settings_status_label.setText(""))

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred while resetting settings: {str(e)}",
                QMessageBox.StandardButton.Ok,
                QMessageBox.StandardButton.NoButton
            )

    def export_settings(self):
        try:
            # Get file path from user
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Settings",
                os.path.expanduser("~/RDR2_NativeViewer_Settings.json"),
                "JSON Files (*.json)"
            )

            if not file_path:
                return  # User canceled

            # Create settings dictionary
            settings_dict: Dict[str, Any] = {
                "register_native_name": self.register_native_name,
                "offset_to_hash": self.offset_to_hash,
                "offset_to_lea": self.offset_to_lea,
            }

            # Write to file
            with open(file_path, 'w') as f:
                json.dump(settings_dict, f, indent=4)

            # Show success message
            self.settings_status_label.setText(
                f"Settings exported to {os.path.basename(file_path)}")
            self.settings_status_label.setStyleSheet("color: green")

            QTimer.singleShot(
                3000, lambda: self.settings_status_label.setText(""))

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred while exporting settings: {str(e)}",
                QMessageBox.StandardButton.Ok,
                QMessageBox.StandardButton.NoButton
            )

    def import_settings(self):
        try:
            # Get file path from user
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Import Settings",
                os.path.expanduser("~"),
                "JSON Files (*.json)"
            )

            if not file_path:
                return  # User canceled

            # Read from file
            with open(file_path, 'r') as f:
                settings_dict = json.load(f)

            # Validate required keys
            required_keys = ["register_native_name",
                             "offset_to_hash", "offset_to_lea"]
            for key in required_keys:
                if key not in settings_dict:
                    QMessageBox.warning(
                        self,
                        "Invalid Settings File",
                        f"The settings file is missing the '{key}' setting.",
                        QMessageBox.StandardButton.Ok,
                        QMessageBox.StandardButton.NoButton
                    )
                    return

            # Update settings
            self.register_native_name = settings_dict["register_native_name"]
            self.offset_to_hash = int(settings_dict["offset_to_hash"])
            self.offset_to_lea = int(settings_dict["offset_to_lea"])

            # Update UI
            self.register_native_name_input.setText(self.register_native_name)

            self.hash_offset_input.setText(f"0x{self.offset_to_hash:X}")
            self.lea_offset_input.setText(f"0x{self.offset_to_lea:X}")

            # Save to QSettings
            self.settings.setValue(
                "register_native_name", self.register_native_name)
            self.settings.setValue("offset_to_hash", self.offset_to_hash)
            self.settings.setValue("offset_to_lea", self.offset_to_lea)

            self.settings.sync()

            # Show success message
            self.settings_status_label.setText(
                f"Settings imported from {os.path.basename(file_path)}")
            self.settings_status_label.setStyleSheet("color: green")

            # Clear the status message after 3 seconds
            QTimer.singleShot(
                3000, lambda: self.settings_status_label.setText(""))

        except json.JSONDecodeError:
            QMessageBox.critical(
                self,
                "Error",
                "The selected file is not a valid JSON file.",
                QMessageBox.StandardButton.Ok,
                QMessageBox.StandardButton.NoButton
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred while importing settings: {str(e)}",
                QMessageBox.StandardButton.Ok,
                QMessageBox.StandardButton.NoButton
            )

    def view_function(self, addr: int) -> None:
        try:
            # Try to use IDA's API if available
            try:
                # Use a dynamic import to avoid errors outside of IDA
                import importlib
                ida_kernwin = importlib.import_module('ida_kernwin')
                ida_kernwin.jumpto(addr)
            except (ImportError, ModuleNotFoundError):
                # If not in IDA, show a message
                QMessageBox.information(
                    self,
                    "View Function",
                    f"Viewing function at {hex(addr)} (In IDA Pro this would jump to the function)"
                )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred while trying to view the function: {str(e)}",
                QMessageBox.StandardButton.Ok,
                QMessageBox.StandardButton.NoButton
            )

    def browse_db_file(self) -> None:
        """Browse for a database file using the NativeDB class."""
        self.DB.browse_db_file()

    def save_natives_to_db(self) -> None:
        """Save natives to SQLite database using the NativeDB class."""
        self.DB.save_natives_to_db(self.natives)

    def load_natives_from_db(self) -> None:
        """Load natives from SQLite database using the NativeDB class."""
        self.DB.load_natives_from_db()

    def show_context_menu(self, position: Any) -> None:
        """Show custom context menu for table items.

        Provides options to copy hash ID, address, function name, etc.
        """
        # Get the item at the right-click position
        row = self.natives_table.rowAt(position.y())
        if row < 0:
            return  # No item at this position

        # Create context menu
        context_menu = QMenu(self)

        # Add menu actions
        copy_hash_action = context_menu.addAction("Copy Hash")
        copy_addr_action = context_menu.addAction("Copy Address")
        copy_func_name_action = context_menu.addAction("Copy Function Name")
        copy_native_name_action = context_menu.addAction("Copy Native Name")
        copy_native_namespace_action = context_menu.addAction(
            "Copy Native Namespace")
        copy_all_action = context_menu.addAction("Copy All Data")

        cursor_pos = QCursor.pos()
        action = context_menu.exec(cursor_pos)

        if not action:
            return  # No action selected

        # Get the data from the row - safely check if items exist
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

        # Handle menu actions
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
        """Reload native functions from the current database.

        If a database file is loaded, refreshes the table with current data.
        Otherwise displays an error message.
        """
        if self.current_db_path:
            self.load_natives_from_db()
        else:
            self.show_status_message("No database loaded to refresh")

    def find_register_native(self):
        """Find the RegisterNative function using native_utils"""
        try:
            # Get the desired function name from the input
            reg_name = self.find_reg_name_input.text().strip()
            if not reg_name:
                reg_name = DEFAULT_REGISTER_NATIVE_NAME
                self.find_reg_name_input.setText(reg_name)

            # Call the FindRegisterNative function
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
                # Handle single address or list of addresses
                if isinstance(reg_address, list):
                    # Multiple addresses found, use the first one
                    if len(reg_address) > 0:
                        address_to_use = reg_address[0]
                        address_text = f"{hex(address_to_use)} (+ {len(reg_address)-1} more)"
                    else:
                        self.find_reg_result.setText(
                            "No valid addresses found.")
                        self.find_reg_result.setStyleSheet("color: red;")
                        return
                else:
                    # Single address found
                    address_to_use = reg_address
                    address_text = hex(address_to_use)

                # Update the result label with the found address
                self.find_reg_result.setText(
                    f"RegisterNative function found at: {address_text}")
                self.find_reg_result.setStyleSheet(
                    "color: green; font-weight: bold;")

                # Ask if the user wants to update the settings with the found function
                reply = QMessageBox.question(
                    self,
                    "Function Found",
                    f"RegisterNative function found at {address_text}.\nDo you want to update your settings with this function name?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes
                )

                if reply == QMessageBox.StandardButton.Yes:
                    # Update register native name in settings
                    self.register_native_name = reg_name
                    self.register_native_name_input.setText(reg_name)
                    self.settings.setValue("register_native_name", reg_name)
                    self.settings.sync()

                    # Show confirmation
                    self.settings_status_label.setText(
                        f"Settings updated with function name: {reg_name}")
                    self.settings_status_label.setStyleSheet("color: green")

                    # Clear the status message after 3 seconds
                    QTimer.singleShot(
                        3000, lambda: self.settings_status_label.setText(""))

                # Try to view the function in IDA if possible
                try:
                    import importlib
                    ida_kernwin = importlib.import_module('ida_kernwin')
                    # Use the validated address
                    ida_kernwin.jumpto(address_to_use)
                except (ImportError, ModuleNotFoundError):
                    pass  # We're not in IDA, no need to show a message

            else:
                # Update the result label if the function was not found
                self.find_reg_result.setText(
                    "Could not find RegisterNative function. Check IDA console for details.")
                self.find_reg_result.setStyleSheet("color: red;")

        except Exception as e:
            # Update the result label with the error
            self.find_reg_result.setText(f"Error: {str(e)}")
            self.find_reg_result.setStyleSheet("color: red;")

    def search_by_signature(self):
        """Search for RegisterNative function using a custom signature"""
        try:
            # Get the signature from the input field
            signature = self.reg_signature_input.text().strip()
            if not signature:
                self.find_reg_result.setText("Error: No signature provided")
                self.find_reg_result.setStyleSheet("color: red;")
                return

            # Call FindRegisterNative with the custom signature
            try:
                reg_address = FindRegisterNative(signature)
            except Exception as e:
                self.find_reg_result.setText(f"Error during search: {str(e)}")
                self.find_reg_result.setStyleSheet("color: red;")
                return

            # Process the result
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

                # Update the result display
                self.find_reg_result.setText(
                    f"Found address using signature: {address_text}")
                self.find_reg_result.setStyleSheet(
                    "color: green; font-weight: bold;")

                # Ask if the user wants to view the function
                reply = QMessageBox.question(
                    self,
                    "Function Found",
                    f"RegisterNative function found at {address_text}.\nDo you want to view this function?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes
                )

                if reply == QMessageBox.StandardButton.Yes:
                    # Try to view the function in IDA
                    try:
                        import importlib
                        ida_kernwin = importlib.import_module('ida_kernwin')
                        ida_kernwin.jumpto(address_to_use)
                    except (ImportError, ModuleNotFoundError):
                        QMessageBox.information(
                            self,
                            "View Function",
                            f"Would jump to function at {address_text} in IDA Pro"
                        )
            else:
                self.find_reg_result.setText(
                    "No matches found for the signature")
                self.find_reg_result.setStyleSheet("color: red;")

        except Exception as e:
            self.find_reg_result.setText(f"Error: {str(e)}")
            self.find_reg_result.setStyleSheet("color: red;")

    def find_game_build(self):
        """Find the game build string"""
        try:

            build = FindGameBuild()

            if build:
                if isinstance(build, list):
                    # Multiple builds found
                    build_text = ", ".join(str(b) for b in build)
                    self.build_result.setText(
                        f"Multiple game builds found: {build_text}")
                else:
                    # Single build found
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
    """Database management class for native functions.

    This class handles saving, loading, and managing native function data
    in SQLite databases.
    """

    def __init__(self, parent: 'NativeViewerUI'):
        """Initialize the database manager with a parent UI reference.

        Args:
            parent: Parent UI object with necessary UI components and settings
        """
        self.parent: 'NativeViewerUI' = parent

    def browse_db_file(self) -> Optional[str]:
        """Open a file dialog to select a database file.

        Returns:
            str: Selected file path or None if canceled
        """
        try:
            if not self.parent:
                print("Error: Parent UI reference is None")
                return None

            # Use a default path from settings or home directory
            default_path = str(self.parent.settings.value(
                "last_db_path", os.path.expanduser("~/RDR2_Natives.db")))

            file_path, _ = QFileDialog.getSaveFileName(
                self.parent,
                "Select SQLite Database File",
                default_path,
                "SQLite Database (*.db);;All Files (*)"
            )

            if file_path:
                # Set the path in the text field
                self.parent.db_file_path.setText(file_path)

                # Store the directory for next time
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
        """Save natives to SQLite database.

        Args:
            natives (list): List of native function dictionaries to save
            db_path (str, optional): Path to the database file. If None, will use UI path
            register_native_name (str, optional): Name of the RegisterNative function

        Returns:
            bool: True if successful, False otherwise
        """
        # Initialize conn to None to avoid unbound variable in exception handling
        conn = None

        try:
            # Check if we have natives to save
            if not natives:
                if self.parent:
                    QMessageBox.warning(
                        self.parent,
                        "No Data",
                        "No native functions to save. Please load natives first.",
                        QMessageBox.StandardButton.Ok,
                        QMessageBox.StandardButton.NoButton
                    )
                return False

            # Get the database file path
            if db_path is None and self.parent:
                db_path = self.parent.db_file_path.text().strip()

            if not db_path:
                if self.parent:
                    QMessageBox.warning(
                        self.parent,
                        "No Database File",
                        "Please specify a database file path.",
                        QMessageBox.StandardButton.Ok,
                        QMessageBox.StandardButton.NoButton
                    )
                return False

            # Ensure we have a valid path
            db_path = str(db_path)

            # Confirm overwrite if file exists
            if os.path.exists(db_path) and self.parent:
                reply = QMessageBox.question(
                    self.parent,
                    "File Exists",
                    f"The file {os.path.basename(db_path)} already exists. Do you want to overwrite it?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )

                if reply == QMessageBox.StandardButton.No:
                    return False

            # Create progress dialog if we have a parent UI
            progress = None
            if self.parent:
                progress = QProgressDialog(
                    "Saving natives to database...", "Cancel", 0, len(natives), self.parent)
                progress.setWindowTitle("Saving to Database")
                progress.setValue(0)

            # Connect to database
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Create tables if they don't exist
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

            # Create a table for metadata
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            ''')

            # Begin transaction for better performance
            conn.isolation_level = None  # Control transactions manually
            conn.execute("BEGIN")

            # Store metadata
            timestamp = datetime.datetime.now().isoformat()
            cursor.execute("INSERT OR REPLACE INTO metadata VALUES (?, ?)",
                           ("timestamp", timestamp))
            cursor.execute("INSERT OR REPLACE INTO metadata VALUES (?, ?)",
                           ("source", "RDR2 Native Viewer"))

            # Use provided register name or get from parent
            if register_native_name is None and self.parent:
                register_native_name = str(self.parent.register_native_name)

            if register_native_name:
                cursor.execute("INSERT OR REPLACE INTO metadata VALUES (?, ?)",
                               ("register_native_name", register_native_name))

            # Insert natives into database
            for i, native in enumerate(natives):
                # Check if operation was cancelled (if progress dialog exists)
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

                # Update progress if dialog exists
                if progress:
                    progress.setValue(i + 1)

            # Commit transaction
            conn.commit()
            conn.close()

            # Show success message if parent UI exists
            if self.parent:
                # Get just the filename for display
                db_filename = os.path.basename(db_path)

                self.parent.show_status_message(
                    f"Successfully saved {len(natives)} natives to {db_filename}")

                # Store the path in settings
                self.parent.settings.setValue("last_db_path", db_path)

            return True

        except sqlite3.Error as e:
            # Make sure to rollback any active transaction on error
            try:
                if conn is not None:
                    conn.rollback()
                    conn.close()
            except:
                pass  # Connection might already be closed

            if self.parent:
                QMessageBox.critical(
                    self.parent,
                    "Database Error",
                    f"A database error occurred: {str(e)}",
                    QMessageBox.StandardButton.Ok,
                    QMessageBox.StandardButton.NoButton
                )
                self.parent.show_status_message(f"Error: {str(e)}")

            print(f"Database error: {str(e)}")

            return False

        except Exception as e:
            if self.parent:
                QMessageBox.critical(
                    self.parent,
                    "Error",
                    f"An error occurred: {str(e)}",
                    QMessageBox.StandardButton.Ok,
                    QMessageBox.StandardButton.NoButton
                )
                self.parent.show_status_message(f"Error: {str(e)}")

            return False

    def load_natives_from_db(self, db_path: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
        """Load natives from SQLite database.

        Args:
            db_path (str, optional): Path to the database file. If None, will use UI path

        Returns:
            list: List of native function dictionaries, or None if failed
        """
        conn = None
        try:
            # Get database path
            if db_path is None and self.parent:
                db_path = self.parent.db_file_path.text().strip()

                if not db_path:
                    # Try to get last used path from settings
                    db_path = str(
                        self.parent.settings.value("last_db_path", ""))
                    if db_path:
                        self.parent.db_file_path.setText(db_path)
                    else:
                        if self.parent:
                            QMessageBox.warning(
                                self.parent,
                                "No Database File",
                                "Please specify a database file path.",
                                QMessageBox.StandardButton.Ok,
                                QMessageBox.StandardButton.NoButton
                            )
                        return None

            # Make sure we have a valid path by this point
            if not db_path:
                print("Error: No database path provided")
                return None

            # Check if file exists
            if not os.path.exists(db_path):
                if self.parent:
                    QMessageBox.warning(
                        self.parent,
                        "File Not Found",
                        f"The database file {db_path} does not exist.",
                        QMessageBox.StandardButton.Ok,
                        QMessageBox.StandardButton.NoButton
                    )
                return None

            # Connect to database
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Check if natives table exists
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='natives'")
            if not cursor.fetchone():
                if self.parent:
                    QMessageBox.warning(
                        self.parent,
                        "Invalid Database",
                        "This database does not contain a natives table.",
                        QMessageBox.StandardButton.Ok,
                        QMessageBox.StandardButton.NoButton
                    )
                conn.close()
                return None

            # Get metadata if available
            metadata_str = "No metadata available"
            try:
                cursor.execute("SELECT key, value FROM metadata")
                metadata = dict(cursor.fetchall())
                metadata_str = "\n".join(
                    [f"{k}: {v}" for k, v in metadata.items()])
            except sqlite3.Error:
                metadata_str = "No metadata available"

            # Ask for confirmation if UI parent exists
            if self.parent:
                # Get just the filename for display
                db_filename = os.path.basename(str(db_path))

                reply = QMessageBox.question(
                    self.parent,
                    "Load Natives",
                    f"Load natives from {db_filename}?\n\nDatabase Information:\n{metadata_str}",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes
                )

                if reply == QMessageBox.StandardButton.No:
                    conn.close()
                    return None

            # Count total natives
            cursor.execute("SELECT COUNT(*) FROM natives")
            total_natives = cursor.fetchone()[0]

            # Create progress dialog if UI parent exists
            progress = None
            if self.parent:
                progress = QProgressDialog(
                    "Loading natives from database...", "Cancel", 0, total_natives, self.parent)
                progress.setWindowTitle("Loading from Database")
                progress.setValue(0)

            # Get column information
            cursor.execute("PRAGMA table_info(natives)")
            columns = {column_info[1] for column_info in cursor.fetchall()}

            # List to store loaded natives
            natives: List[Dict[str, Any]] = []

            # Check for extended schema with native_name and namespace
            has_extended_schema = 'native_name' in columns and 'namespace' in columns

            # Determine query based on schema
            if has_extended_schema:
                query = "SELECT hash, address, name, native_name, namespace FROM natives"
            else:
                query = "SELECT hash, address, name FROM natives"

            # Execute query
            cursor.execute(query)

            # Process results
            for i, row in enumerate(cursor.fetchall()):
                # Check if operation was cancelled (if progress exists)
                if progress and progress.wasCanceled():
                    conn.close()
                    if self.parent:
                        self.parent.show_status_message("Operation cancelled")

                    return None

                # Unpack row based on schema
                if has_extended_schema:
                    hash_val, addr, name, native_name, namespace = row
                else:
                    hash_val, addr, name = row
                    native_name = ""  # Default empty value
                    namespace = ""    # Default empty value

                # Convert hex string to int for internal storage
                int_hash = int(hash_val, 16) if hash_val.startswith(
                    '0x') else int(hash_val)
                int_addr = int(addr, 16) if addr.startswith(
                    '0x') else int(addr)

                # Create native entry
                native_entry: Dict[str, Any] = {
                    'hash': int_hash,
                    'hex_hash': hash_val,
                    'addr': int_addr,
                    'hex_addr': addr,
                    'name': name,
                    'native_name': native_name,
                    'namespace': namespace
                }

                # Pre-compute search string for faster filtering
                native_entry['search_string'] = (
                    native_entry['hex_hash'].lower() + ' ' +
                    native_entry['hex_addr'].lower() + ' ' +
                    native_entry['name'].lower() + ' ' +
                    native_entry['native_name'].lower() + ' ' +
                    native_entry['namespace'].lower()
                )

                natives.append(native_entry)

                # Update progress if UI parent exists
                if progress:
                    progress.setValue(i + 1)

            conn.close()

            # Update UI components if parent exists
            if self.parent:
                # Get just the filename for display
                db_filename = os.path.basename(str(db_path))

                # Update parent's natives data
                self.parent.natives = natives

                # Update table
                self.parent.update_table()

                # Update data source label
                self.parent.data_source_label.setText(
                    f"Data Source: SQLite Database ({db_filename})")
                self.parent.data_source_label.setStyleSheet(
                    "font-weight: bold; color: green;")

                # Show success message
                self.parent.show_status_message(
                    f"Successfully loaded {len(natives)} natives from {db_filename}")

                # Update search box placeholder to show we have data
                self.parent.search_box.setPlaceholderText(
                    f"Search {len(natives)} loaded natives...")

                # Store the current db path
                self.parent.current_db_path = str(db_path)

            return natives

        except sqlite3.Error as e:
            # Make sure to close connection on error
            try:
                if conn is not None:
                    conn.close()
            except:
                pass  # Connection might already be closed

            if self.parent:
                QMessageBox.critical(
                    self.parent,
                    "Database Error",
                    f"A database error occurred: {str(e)}",
                    QMessageBox.StandardButton.Ok,
                    QMessageBox.StandardButton.NoButton
                )
                self.parent.show_status_message(f"Error: {str(e)}")

            print(f"Database error: {str(e)}")

            return None

        except Exception as e:
            if self.parent:
                QMessageBox.critical(
                    self.parent,
                    "Error",
                    f"An error occurred: {str(e)}",
                    QMessageBox.StandardButton.Ok,
                    QMessageBox.StandardButton.NoButton
                )
                self.parent.show_status_message(f"Error: {str(e)}")

            return None


# Global reference to prevent garbage collection
_native_viewer_window = None


def run():
    """Run the plugin"""
    global _native_viewer_window

    print("RDR2 Native Viewer")
    print("------------------")

    try:
        window = None
        app = QApplication.instance()
        if app is None:
            app = QApplication([])

        # Ensure we have a QApplication instance, not just QCoreApplication
        if isinstance(app, QApplication):
            window = NativeViewerUI(app.clipboard())
            window.show()

            window.activateWindow()
            window.raise_()

            app.exec()

            _native_viewer_window = window  # Keep a global reference
        else:
            print("Error: Could not get QApplication instance")
            return None

        return _native_viewer_window
    except Exception as e:
        print(f"Error running UI: {str(e)}")
        return None


if __name__ == "__main__":
    run()
