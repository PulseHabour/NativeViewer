from typing import Optional, List, Dict, Any, Callable
import os
import json
import sqlite3
import datetime

# IDA Pro imports
from idaapi import require  # noqa
require('NV_Utils')  # noqa
from NV_Utils import (  # noqa
    OFFSET_TO_HASH,
    OFFSET_TO_LEA,
    FindGameBuild,
    FindRegisterNative,
    get_all_natives_from_ida
)

# PySide6 imports
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


# Application Constants
DEFAULT_REGISTER_NATIVE_NAME = "RegisterNative"
DEFAULT_DATABASE_NAME = "RDR2_Natives.db"
DEFAULT_NATIVES_JSON = "rdr3natives.json"
APP_NAME = "RDR2 Native Viewer"
APP_ORGANIZATION = "RDR2Tools"
APP_DOMAIN = "NativeViewer"

# UI Constants
WINDOW_WIDTH = 1000
WINDOW_HEIGHT = 700
FILTER_DELAY_MS = 300
PROGRESS_MESSAGE_DURATION_MS = 3000

# Discord Community
DISCORD_INVITE_CODE = "S4pRcx5Sua"


class UIHelpers:
    """
    Utility class providing static methods for creating common UI components.

    This class centralizes UI element creation to ensure consistency across
    the application and provide reusable UI components with standardized styling.
    """

    @staticmethod
    def create_section_label(text: str, tooltip: Optional[str] = None) -> QLabel:
        """
        Create a section label with optional tooltip.

        Args:
            text: The label text to display
            tooltip: Optional tooltip text for the label

        Returns:
            QLabel: Configured label widget
        """
        label = QLabel(text)
        if tooltip:
            label.setToolTip(tooltip)
        return label

    @staticmethod
    def create_separator() -> QFrame:
        """
        Create a horizontal line separator for UI sections.

        Returns:
            QFrame: Horizontal line separator widget
        """
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        return line

    @staticmethod
    def create_button(
        text: str,
        on_click: Callable[[], Any],
        tooltip: Optional[str] = None
    ) -> QPushButton:
        """
        Create a button with click handler and optional tooltip.

        Args:
            text: Button text to display
            on_click: Callback function to execute when button is clicked
            tooltip: Optional tooltip text for the button

        Returns:
            QPushButton: Configured button widget
        """
        button = QPushButton(text)
        if tooltip:
            button.setToolTip(tooltip)
        button.clicked.connect(lambda checked=False: on_click())
        return button

    @staticmethod
    def show_confirmation_dialog(
        parent: QWidget,
        title: str,
        text: str,
        *,
        default_yes: bool = True
    ) -> bool:
        """
        Show a yes/no confirmation dialog.

        Args:
            parent: Parent widget for the dialog
            title: Dialog window title
            text: Dialog message text
            default_yes: Whether 'Yes' should be the default button

        Returns:
            bool: True if user clicked 'Yes', False otherwise
        """
        default_button = (
            QMessageBox.StandardButton.Yes if default_yes
            else QMessageBox.StandardButton.No
        )
        reply = QMessageBox.question(
            parent,
            title,
            text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            default_button,
        )
        return reply == QMessageBox.StandardButton.Yes

    @staticmethod
    def show_info_message(parent: QWidget, title: str, text: str) -> None:
        """
        Show an information message dialog.

        Args:
            parent: Parent widget for the dialog
            title: Dialog window title
            text: Information message text
        """
        QMessageBox.information(
            parent,
            title,
            text,
            QMessageBox.StandardButton.Ok,
            QMessageBox.StandardButton.NoButton
        )

    @staticmethod
    def show_warning_message(parent: QWidget, title: str, text: str) -> None:
        """
        Show a warning message dialog.

        Args:
            parent: Parent widget for the dialog
            title: Dialog window title
            text: Warning message text
        """
        QMessageBox.warning(
            parent,
            title,
            text,
            QMessageBox.StandardButton.Ok,
            QMessageBox.StandardButton.NoButton
        )

    @staticmethod
    def show_error_message(parent: QWidget, title: str, text: str) -> None:
        """
        Show an error message dialog.

        Args:
            parent: Parent widget for the dialog
            title: Dialog window title
            text: Error message text
        """
        QMessageBox.critical(
            parent,
            title,
            text,
            QMessageBox.StandardButton.Ok,
            QMessageBox.StandardButton.NoButton
        )

    @staticmethod
    def create_progress_dialog(
        parent: QWidget,
        title: str,
        label_text: str,
        maximum: int
    ) -> QProgressDialog:
        """
        Create a progress dialog for long-running operations.

        Args:
            parent: Parent widget for the dialog
            title: Dialog window title
            label_text: Progress label text
            maximum: Maximum progress value

        Returns:
            QProgressDialog: Configured progress dialog
        """
        dialog = QProgressDialog(label_text, "Cancel", 0, maximum, parent)
        dialog.setWindowTitle(title)
        dialog.setValue(0)
        return dialog


class NativeViewerUI(QMainWindow):
    """
    Main application window for the RDR2 Native Viewer.

    This class provides a comprehensive GUI for loading, viewing, and managing
    RDR2 native functions from various sources including IDA Pro and SQLite databases.
    Features include advanced filtering, native name resolution, and settings management.
    """

    def __init__(self, clipboard: QClipboard):
        """
        Initialize the Native Viewer UI.

        Args:
            clipboard: Qt clipboard instance for copy operations
        """
        super().__init__()

        # Core attributes
        self.clipboard: QClipboard = clipboard
        self.app = APP_DOMAIN

        # Data attributes
        self.natives: List[Dict[str, Any]] = []
        self.native_names_map: Dict[str, Dict[str, str]] = {}
        self.current_db_path: Optional[str] = None
        self.last_filtered_natives: List[Dict[str, Any]] = []
        self.last_search_text: str = ""

        # UI component attributes (will be initialized in setup methods)
        self.filter_hash_cb: QCheckBox
        self.filter_addr_cb: QCheckBox
        self.filter_name_cb: QCheckBox
        self.filter_native_name_cb: QCheckBox
        self.filter_namespace_cb: QCheckBox
        self.search_box: QLineEdit
        self.natives_table: QTableWidget
        self.natives_count_label: QLabel

        # Settings UI components
        self.register_native_name_input: QLineEdit
        self.hash_offset_input: QLineEdit
        self.lea_offset_input: QLineEdit
        self.settings_status_label: QLabel
        self.db_file_path: QLineEdit

        # Tools UI components
        self.ida_register_name_input: QLineEdit
        self.ida_load_status: QLabel
        self.find_reg_name_input: QLineEdit
        self.reg_signature_input: QLineEdit
        self.find_reg_result: QLabel
        self.build_result: QLabel
        self.natives_json_status: QLabel

        # Timer for filtering
        self.filter_timer = QTimer()
        self.filter_timer.setSingleShot(True)
        self.filter_timer.timeout.connect(self.filter_table)

        # Database handler
        self.database = NativeViewerDatabase(self)

        # Initialize UI
        self._initialize_window()
        self._initialize_settings()
        self._setup_ui()

        # Load data
        self.load_native_names()
        self.prompt_load_natives()

    def _initialize_window(self) -> None:
        """Initialize the main window properties."""
        self.setWindowTitle(APP_NAME)
        self.setGeometry(100, 100, WINDOW_WIDTH, WINDOW_HEIGHT)

        # Setup status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

    def _initialize_settings(self) -> None:
        """Initialize application settings."""
        self.settings = QSettings(APP_ORGANIZATION, APP_DOMAIN)
        self.load_settings()

    def _setup_ui(self) -> None:
        """Setup the main UI layout and tabs."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # Setup all tabs
        self._setup_natives_tab()
        self._setup_settings_tab()
        self._setup_tools_tab()
        self._setup_misc_tab()

    def _setup_natives_tab(self) -> None:
        """Setup the natives viewing tab with table and filtering."""
        natives_tab = QWidget()
        layout = QVBoxLayout(natives_tab)
        self.tab_widget.addTab(natives_tab, "Natives")

        # Setup search and filter controls
        self._setup_search_controls(layout)

        # Setup natives count label
        self.natives_count_label = QLabel("0/0")
        self.natives_count_label.setStyleSheet(
            "font-weight: bold; color: white;")
        layout.addWidget(self.natives_count_label)

        # Setup natives table
        self._setup_natives_table(layout)

    def _setup_search_controls(self, layout: QVBoxLayout) -> None:
        """Setup search box and filter checkboxes."""
        top_layout = QHBoxLayout()

        # Search box
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText(
            "Enter hash or function name to search")
        self.search_box.textChanged.connect(self._start_filter_timer)
        search_layout.addWidget(self.search_box)

        # Filter checkboxes
        filter_layout = self._create_filter_checkboxes()

        search_container = QVBoxLayout()
        search_container.addLayout(search_layout)
        search_container.addLayout(filter_layout)

        top_layout.addLayout(search_container, 3)
        export_layout = QHBoxLayout()  # Placeholder for export controls
        top_layout.addLayout(export_layout, 1)

        layout.addLayout(top_layout)

    def _create_filter_checkboxes(self) -> QHBoxLayout:
        """Create filter checkbox controls."""
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by:"))

        # Create filter checkboxes with their labels
        filter_configs = [
            ("filter_hash_cb", "Hash", True),
            ("filter_addr_cb", "Address", True),
            ("filter_name_cb", "Function Name", True),
            ("filter_native_name_cb", "Native Name", True),
            ("filter_namespace_cb", "Namespace", True),
        ]

        for attr_name, label, default_checked in filter_configs:
            checkbox = QCheckBox(label)
            checkbox.setChecked(default_checked)
            checkbox.stateChanged.connect(self._start_filter_timer)
            setattr(self, attr_name, checkbox)
            filter_layout.addWidget(checkbox)

        return filter_layout

    def _setup_natives_table(self, layout: QVBoxLayout) -> None:
        """Setup the natives data table."""
        self.natives_table = QTableWidget()
        self.natives_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        self.natives_table.setColumnCount(6)
        self.natives_table.setHorizontalHeaderLabels([
            "Hash", "Address", "Function Name",
            "Native Name", "Native Namespace", "Actions"
        ])

        # Setup context menu
        self.natives_table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self.natives_table.customContextMenuRequested.connect(
            self.show_context_menu)

        # Configure table headers
        self._configure_table_headers()

        layout.addWidget(self.natives_table)

    def _configure_table_headers(self) -> None:
        """Configure table header properties and resize modes."""
        # Hide vertical header (row numbers)
        vertical_header = self.natives_table.verticalHeader()
        if vertical_header:
            vertical_header.setVisible(False)

        # Configure horizontal header
        header = self.natives_table.horizontalHeader()
        if header:
            resize_mode = QHeaderView.ResizeMode.ResizeToContents
            for column in range(5):  # Columns 0-4
                header.setSectionResizeMode(column, resize_mode)
            header.setStretchLastSection(True)  # Last column stretches

    def _setup_settings_tab(self):
        settings_tab = QWidget()
        layout = QVBoxLayout(settings_tab)
        self.tab_widget.addTab(settings_tab, "Settings")
        layout.addWidget(UIHelpers.create_section_label(
            "<b>Function Location Settings:</b>"))
        reg_name_layout = QHBoxLayout()
        reg_name_layout.addWidget(QLabel("RegisterNative Function Name:"))
        self.register_native_name_input = QLineEdit()
        self.register_native_name_input.setText(str(self.register_native_name))
        reg_name_layout.addWidget(self.register_native_name_input)
        layout.addLayout(reg_name_layout)
        layout.addWidget(UIHelpers.create_separator())
        layout.addWidget(UIHelpers.create_section_label(
            "<b>Offset Settings:</b>"))
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

        save_settings_button = UIHelpers.create_button(
            "Save Settings", self.save_settings)
        buttons_layout.addWidget(save_settings_button)

        reset_settings_button = UIHelpers.create_button(
            "Reset to Defaults", self.reset_settings)
        buttons_layout.addWidget(reset_settings_button)

        layout.addLayout(buttons_layout)

        io_buttons_layout = QHBoxLayout()

        import_settings_button = UIHelpers.create_button(
            "Import Settings", self.import_settings)
        io_buttons_layout.addWidget(import_settings_button)

        layout.addLayout(io_buttons_layout)

        self.settings_status_label = QLabel("")
        layout.addWidget(self.settings_status_label)

        layout.addWidget(UIHelpers.create_separator())

        sqlite_label = UIHelpers.create_section_label(
            "<b>SQLite Database Operations:</b>")
        sqlite_label.setToolTip(
            "Save and load native functions to/from a SQLite database")
        layout.addWidget(sqlite_label)

        save_db_layout = QHBoxLayout()
        save_db_layout.addWidget(QLabel("Database File:"))
        self.db_file_path = QLineEdit()
        self.db_file_path.setPlaceholderText("Path to SQLite database file")
        save_db_layout.addWidget(self.db_file_path)

        browse_button = UIHelpers.create_button(
            "Browse", self.database.browse_db_file)
        save_db_layout.addWidget(browse_button)

        layout.addLayout(save_db_layout)

        db_buttons_layout = QHBoxLayout()

        save_natives_button = UIHelpers.create_button(
            "Save Natives to DB", lambda: self.database.save_natives_to_db(self.natives))
        save_natives_button.setToolTip(
            "Save currently loaded native functions to the specified database file")
        db_buttons_layout.addWidget(save_natives_button)

        load_natives_button = UIHelpers.create_button(
            "Load Natives from DB", lambda: self.database.load_natives_from_db())
        load_natives_button.setToolTip(
            "Load native functions from the specified database file")
        db_buttons_layout.addWidget(load_natives_button)

        layout.addLayout(db_buttons_layout)

        layout.addStretch(1)

    def _setup_tools_tab(self):

        tools_tab = QWidget()
        layout = QVBoxLayout(tools_tab)
        self.tab_widget.addTab(tools_tab, "Tools")

        load_ida_label = UIHelpers.create_section_label(
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

        load_ida_button = UIHelpers.create_button(
            "Load Natives from IDA", self.load_natives_from_ida)
        load_ida_button.setToolTip(
            "Scan IDA Pro for native functions using the specified RegisterNative function")
        load_ida_layout.addWidget(load_ida_button)

        layout.addLayout(load_ida_layout)

        self.ida_load_status = QLabel("")
        layout.addWidget(self.ida_load_status)

        layout.addWidget(UIHelpers.create_separator())

        find_reg_label = UIHelpers.create_section_label(
            "<b>Find RegisterNative Function:</b>")
        find_reg_label.setToolTip(
            "Find the function that registers native functions in the IDA")
        layout.addWidget(find_reg_label)

        find_reg_layout = QHBoxLayout()
        find_reg_layout.addWidget(QLabel("Function Name:"))
        self.find_reg_name_input = QLineEdit()
        self.find_reg_name_input.setText(str(self.register_native_name))
        find_reg_layout.addWidget(self.find_reg_name_input)

        find_reg_button = UIHelpers.create_button(
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

        sig_search_button = UIHelpers.create_button(
            "Search by Signature", self.search_by_signature)
        sig_layout.addWidget(sig_search_button)

        layout.addLayout(sig_layout)

        self.find_reg_result = QLabel("Result will be shown here")
        layout.addWidget(self.find_reg_result)

        layout.addWidget(UIHelpers.create_separator())

        build_label = UIHelpers.create_section_label("<b>Find Game Build:</b>")
        build_label.setToolTip(
            "Find the game build version string in the executable")
        layout.addWidget(build_label)

        build_layout = QHBoxLayout()
        build_search_button = UIHelpers.create_button(
            "Find Game Build", self.find_game_build)
        build_layout.addWidget(build_search_button)

        layout.addLayout(build_layout)

        self.build_result = QLabel("Game build will be shown here")
        layout.addWidget(self.build_result)

        layout.addWidget(UIHelpers.create_separator())

        natives_json_label = UIHelpers.create_section_label(
            "<b>RDR3natives.json Operations:</b>")
        natives_json_label.setToolTip(
            "Work with RDR3natives.json file to get native names and namespaces")
        layout.addWidget(natives_json_label)

        natives_json_layout = QHBoxLayout()

        load_natives_json_button = UIHelpers.create_button(
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
        layout.addWidget(UIHelpers.create_separator())
        layout.addWidget(QLabel("<b>Community & Support:</b>"))
        discord_layout = QHBoxLayout()
        discord_layout.addWidget(QLabel("Join our Discord community:"))
        discord_button = UIHelpers.create_button(
            "Join Discord Server", self.open_discord_invite)
        discord_layout.addWidget(discord_button)
        layout.addLayout(discord_layout)
        discord_info = QLabel(f"Discord Invite: {DISCORD_INVITE_CODE}")
        discord_info.setStyleSheet("color: #5865F2; font-weight: bold;")
        layout.addWidget(discord_info)
        layout.addStretch(1)

    def open_discord_invite(self) -> None:
        full_invite = f"https://discord.gg/{DISCORD_INVITE_CODE}"

        # get os type
        if os.name == 'nt':  # Windows
            os.system(f'start {full_invite}')
        elif os.name == 'posix':  # macOS
            os.system(f'open {full_invite}')

    def prompt_load_natives(self) -> None:
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Load Natives")
        msg_box.setText("Would you like to load natives?")

        ida_button = msg_box.addButton(
            "Load from IDA", QMessageBox.ButtonRole.ActionRole
        )
        db_button = msg_box.addButton(
            "Load from Database", QMessageBox.ButtonRole.ActionRole
        )
        msg_box.addButton("Continue", QMessageBox.ButtonRole.RejectRole)

        msg_box.exec()
        clicked_button = msg_box.clickedButton()

        if clicked_button == ida_button:
            self.load_natives_from_ida()
        elif clicked_button == db_button:
            self.database.load_natives_from_db()

    def load_natives_from_ida(self) -> None:

        self._clear_natives_data()

        register_func_name = self._get_register_function_name()

        self._update_ida_load_status("Loading natives from IDA...", "blue")
        self.show_status_message("Loading natives from IDA...")

        try:
            raw_natives = get_all_natives_from_ida(
                register_native_name=register_func_name)

            if not raw_natives:
                error_msg = (
                    f"No native functions found using '{register_func_name}'. "
                    "Check IDA console for details."
                )
                self._handle_ida_load_error(error_msg)
                return

            self._process_raw_natives(raw_natives)

            self._finalize_ida_load_success(len(self.natives))

        except Exception as e:
            error_msg = f"Failed to load natives: {str(e)}"
            self._handle_ida_load_error(error_msg)
            print(f"Error in load_natives_from_ida: {str(e)}")

    def _clear_natives_data(self) -> None:
        """Clear existing natives data and table."""
        self.natives_table.setRowCount(0)
        self.natives = []

    def _get_register_function_name(self) -> str:
        """Get the register function name from appropriate input field."""
        if hasattr(self, 'ida_register_name_input'):
            func_name = self.ida_register_name_input.text().strip()
        else:
            func_name = self.register_native_name_input.text().strip()

        return func_name if func_name else DEFAULT_REGISTER_NATIVE_NAME

    def _update_ida_load_status(self, message: str, color: str) -> None:
        """Update IDA load status label if it exists."""
        if hasattr(self, 'ida_load_status'):
            self.ida_load_status.setText(message)
            self.ida_load_status.setStyleSheet(f"color: {color}")

    def _process_raw_natives(self, raw_natives: List[tuple[int, int, str]]) -> None:
        """
        Process raw native data from IDA into structured format.

        Args:
            raw_natives: List of tuples containing (hash, address, function_name)
        """
        for hash_val, func_addr, func_name in raw_natives:
            hash_str = f"{hash_val:016X}"

            native_name = ""
            namespace = ""
            if hash_str in self.native_names_map:
                native_info = self.native_names_map[hash_str]
                native_name = native_info.get('name', '')
                namespace = native_info.get('namespace', '')

            native_entry: Dict[str, Any] = {
                'hash': hash_val,
                'hex_hash': f"0x{hash_val:016X}",
                'addr': func_addr,
                'hex_addr': f"0x{func_addr:X}",
                'name': func_name,
                'native_name': native_name,
                'namespace': namespace
            }

            native_entry['search_string'] = self._generate_search_string(
                native_entry)
            self.natives.append(native_entry)

    def _finalize_ida_load_success(self, count: int) -> None:
        """Finalize successful IDA load operation."""
        self.update_table()

        self.update_natives_count_display(count, count)

        self.search_box.setPlaceholderText(f"Search {count} loaded natives...")

        success_msg = f"Successfully loaded {count} native functions."
        self.show_status_message(success_msg)
        self._update_ida_load_status(success_msg, "green")

    def _handle_ida_load_error(self, error_msg: str) -> None:
        """Handle errors during IDA load operation."""
        self.show_status_message(error_msg, error=True)
        self._update_ida_load_status(error_msg, "red")

    def show_status_message(self, message: str, error: bool = False) -> None:
        if error:
            self.status_bar.setStyleSheet("color: red; font-weight: bold;")
            QMessageBox.critical(
                self,
                "Error",
                message,
                QMessageBox.StandardButton.Ok,
                QMessageBox.StandardButton.NoButton
            )
        else:
            self.status_bar.setStyleSheet("color: green;")
        self.status_bar.showMessage(message)

    def load_native_names(self) -> None:

        try:
            json_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                DEFAULT_NATIVES_JSON
            )

            if not os.path.exists(json_path):
                print(f"RDR3natives.json not found at {json_path}")
                return

            with open(json_path, 'r', encoding='utf-8') as file:
                native_data = json.load(file)

            self.native_names_map = {}

            # Process each namespace and its natives
            for namespace, natives in native_data.items():
                for hash_str, native_info in natives.items():
                    # Normalize hash string format
                    normalized_hash = self._normalize_hash_string(hash_str)

                    self.native_names_map[normalized_hash] = {
                        "name": native_info.get("name", ""),
                        "namespace": namespace
                    }

            print(f"Loaded {len(self.native_names_map)} native names and "
                  f"namespaces from {json_path}")

        except Exception as e:
            print(f"Error loading native names: {str(e)}")

    def _normalize_hash_string(self, hash_str: str) -> str:
        """
        Normalize hash string format for consistent lookup.

        Args:
            hash_str: Hash string from JSON (may or may not have 0x prefix)

        Returns:
            str: Normalized uppercase hash string without 0x prefix
        """
        if hash_str.startswith('0x'):
            return hash_str[2:].upper()
        return hash_str.upper()

    def update_table(self) -> None:
        """
        Update the natives table with current data.

        This method rebuilds the entire table with the current natives data,
        ensuring search strings are properly generated for each entry.
        """
        self.natives_table.setRowCount(len(self.natives))
        self.natives_table.setSortingEnabled(False)

        # Ensure all natives have search strings
        for native in self.natives:
            if 'search_string' not in native:
                native['search_string'] = self._generate_search_string(native)

        # Populate table rows
        for row, native in enumerate(self.natives):
            self._insert_native_table_row(row, native)

        self.natives_table.setSortingEnabled(True)

    def _generate_search_string(self, native: Dict[str, Any]) -> str:
        """
        Generate a search string for a native function entry.

        Args:
            native: Native function data dictionary

        Returns:
            str: Lowercase search string containing all searchable fields
        """
        search_fields = [
            native.get('hex_hash', ''),
            native.get('hex_addr', ''),
            native.get('name', ''),
            native.get('native_name', ''),
            native.get('namespace', ''),
        ]
        return ' '.join(field.lower() for field in search_fields)

    def _insert_native_table_row(self, row: int, native: Dict[str, Any]) -> None:
        """
        Insert a single native function entry into the table.

        Args:
            row: Table row index
            native: Native function data dictionary
        """
        # Extract data with defaults
        hex_hash = native.get('hex_hash', '')
        hex_addr = native.get('hex_addr', '')
        name = native.get('name', '')
        native_name = native.get('native_name', '')
        namespace = native.get('namespace', '')

        # Set table items
        self.natives_table.setItem(row, 0, QTableWidgetItem(hex_hash))
        self.natives_table.setItem(row, 1, QTableWidgetItem(hex_addr))
        self.natives_table.setItem(row, 2, QTableWidgetItem(name))
        self.natives_table.setItem(row, 3, QTableWidgetItem(native_name))
        self.natives_table.setItem(row, 4, QTableWidgetItem(namespace))

        # Create view button
        view_button = QPushButton("View Function")
        view_button.setToolTip(f"View function at {hex_addr} in IDA Pro")
        address = native['addr']
        view_button.clicked.connect(
            lambda checked=False, addr=address: self.view_function(int(addr))
        )
        self.natives_table.setCellWidget(row, 5, view_button)

    def _start_filter_timer(self) -> None:
        """Start or restart the filter timer to delay filtering until user stops typing."""
        self.filter_timer.stop()
        self.filter_timer.start(FILTER_DELAY_MS)

    def filter_table(self) -> None:
        """
        Filter the natives table based on search text and filter checkboxes.

        This method applies real-time filtering to the natives table, hiding/showing
        rows based on the search criteria and selected filter options.
        """
        search_text = self.search_box.text().lower()
        total_natives = len(self.natives)

        # If no search text, show all rows
        if not search_text:
            for row in range(self.natives_table.rowCount()):
                self.natives_table.setRowHidden(row, False)
            self.last_filtered_natives = self.natives
            self.last_search_text = search_text
            self.update_natives_count_display(total_natives, total_natives)
            return

        # Get filter options
        filter_options = {
            'hash': self.filter_hash_cb.isChecked(),
            'addr': self.filter_addr_cb.isChecked(),
            'name': self.filter_name_cb.isChecked(),
            'native_name': self.filter_native_name_cb.isChecked(),
            'namespace': self.filter_namespace_cb.isChecked(),
        }

        # If no filters are selected, hide all rows
        if not any(filter_options.values()):
            for row in range(self.natives_table.rowCount()):
                self.natives_table.setRowHidden(row, True)
            self.last_filtered_natives = []
            self.last_search_text = search_text
            self.update_natives_count_display(0, total_natives)
            return

        # Apply filtering
        filtered_natives: List[Dict[str, Any]] = []
        for row in range(self.natives_table.rowCount()):
            if row < len(self.natives):
                native = self.natives[row]
                matches = self._check_native_matches_search(
                    native, search_text, filter_options)

                self.natives_table.setRowHidden(row, not matches)
                if matches:
                    filtered_natives.append(native)
            else:
                self.natives_table.setRowHidden(row, True)

        self.last_filtered_natives = filtered_natives
        self.last_search_text = search_text
        self.update_natives_count_display(len(filtered_natives), total_natives)

    def update_natives_count_display(self, visible_count: int, total_count: int) -> None:
        """
        Update the data source label to show filtered/total natives count.

        Args:
            visible_count: Number of currently visible natives after filtering
            total_count: Total number of loaded natives
        """

        # Update count display
        if visible_count == total_count:
            display_text = f"{total_count}/{total_count}".strip()
        else:
            display_text = f"{visible_count}/{total_count}".strip()

        self.natives_count_label.setText(display_text)

    def _check_native_matches_search(
        self,
        native: Dict[str, Any],
        search_text: str,
        filter_options: Dict[str, bool]
    ) -> bool:
        """
        Check if a native function matches the search criteria.

        Args:
            native: Native function data dictionary
            search_text: Search text to match against
            filter_options: Dictionary of enabled filter options

        Returns:
            bool: True if the native matches the search criteria
        """
        search_fields = [
            ('hash', 'hex_hash'),
            ('addr', 'hex_addr'),
            ('name', 'name'),
            ('native_name', 'native_name'),
            ('namespace', 'namespace'),
        ]

        for filter_key, field_key in search_fields:
            if filter_options[filter_key]:
                field_value = native.get(field_key, '').lower()
                if search_text in field_value:
                    return True

        return False

    def save_settings(self) -> None:
        """
        Save current settings to persistent storage.

        This method validates and saves the user's configuration settings,
        including register function name and offset values.
        """
        try:
            new_register_native_name = self.register_native_name_input.text().strip()

            # Validate offset inputs
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

            # Update instance variables
            self.register_native_name = new_register_native_name
            self.offset_to_hash = new_hash_offset
            self.offset_to_lea = new_lea_offset

            # Save to persistent settings
            self.settings.setValue(
                "register_native_name", self.register_native_name)
            self.settings.setValue("offset_to_hash", self.offset_to_hash)
            self.settings.setValue("offset_to_lea", self.offset_to_lea)
            self.settings.sync()

            # Show success message
            self.settings_status_label.setText(
                "Settings saved successfully! Refresh to apply.")
            self.settings_status_label.setStyleSheet("color: green")

            # Clear message after delay
            QTimer.singleShot(
                PROGRESS_MESSAGE_DURATION_MS,
                lambda: self.settings_status_label.setText("")
            )

        except Exception as e:
            UIHelpers.show_error_message(
                self,
                "Error",
                f"An error occurred while saving settings: {str(e)}"
            )

    def load_settings(self) -> None:
        """
        Load settings from persistent storage.

        This method loads user configuration from QSettings, falling back to
        default values if settings are missing or invalid.
        """
        try:
            # Load register native name
            self.register_native_name = self.settings.value(
                "register_native_name",
                DEFAULT_REGISTER_NATIVE_NAME,
                type=str
            )

            # Load offset values with error handling
            try:
                self.offset_to_hash = self.settings.value(
                    "offset_to_hash",
                    OFFSET_TO_HASH,
                    type=int
                )
                self.offset_to_lea = self.settings.value(
                    "offset_to_lea",
                    OFFSET_TO_LEA,
                    type=int
                )
            except (TypeError, ValueError):
                # Fall back to defaults if conversion fails
                self.offset_to_hash = OFFSET_TO_HASH
                self.offset_to_lea = OFFSET_TO_LEA

        except Exception as e:
            print(f"Error loading settings: {e}")
            # Set all to defaults on any error
            self.register_native_name = DEFAULT_REGISTER_NATIVE_NAME
            self.offset_to_hash = OFFSET_TO_HASH
            self.offset_to_lea = OFFSET_TO_LEA

    def reset_settings(self) -> None:
        """
        Reset all settings to their default values.

        This method asks for user confirmation before resetting all configuration
        settings to their default values and updating the UI accordingly.
        """
        try:
            reply_yes = UIHelpers.show_confirmation_dialog(
                self,
                "Reset Settings",
                "Are you sure you want to reset all settings to default values?",
                default_yes=False,
            )

            if reply_yes:
                # Reset to defaults
                self.register_native_name = DEFAULT_REGISTER_NATIVE_NAME
                self.offset_to_hash = OFFSET_TO_HASH
                self.offset_to_lea = OFFSET_TO_LEA

                # Update UI fields
                self.register_native_name_input.setText(
                    self.register_native_name)
                self.hash_offset_input.setText(f"0x{self.offset_to_hash:X}")
                self.lea_offset_input.setText(f"0x{self.offset_to_lea:X}")

                # Clear persistent settings
                self.settings.clear()
                self.settings.sync()

                # Show confirmation message
                self.settings_status_label.setText(
                    "Settings reset to defaults!")
                self.settings_status_label.setStyleSheet("color: blue")

                QTimer.singleShot(
                    PROGRESS_MESSAGE_DURATION_MS,
                    lambda: self.settings_status_label.setText("")
                )

        except Exception as e:
            UIHelpers.show_error_message(
                self,
                "Error",
                f"An error occurred while resetting settings: {str(e)}"
            )

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
            UIHelpers.show_error_message(self, "Error",
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
                    UIHelpers.show_warning_message(self, "Invalid Settings File",
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
            UIHelpers.show_error_message(
                self, "Error", "The selected file is not a valid JSON file.")
        except Exception as e:
            UIHelpers.show_error_message(self, "Error",
                                         f"An error occurred while importing settings: {str(e)}")

    def view_function(self, addr: int) -> None:
        try:
            try:
                import importlib
                ida_kernwin = importlib.import_module('ida_kernwin')
                ida_kernwin.jumpto(addr)
            except (ImportError, ModuleNotFoundError):
                UIHelpers.show_info_message(self, "View Function",
                                            f"Viewing function at {hex(addr)} (In IDA Pro this would jump to the function)")
        except Exception as e:
            UIHelpers.show_error_message(
                self, "Error", f"An error occurred while trying to view the function: {str(e)}")

    def show_context_menu(self, position: Any) -> None:
        """
        Show context menu for table rows with copy options.

        Args:
            position: Mouse position where the context menu was requested
        """
        row = self.natives_table.rowAt(position.y())
        if row < 0:
            return

        # Create context menu with copy options
        context_menu = QMenu(self)
        copy_actions = [
            ("Copy Hash", 0),
            ("Copy Address", 1),
            ("Copy Function Name", 2),
            ("Copy Native Name", 3),
            ("Copy Native Namespace", 4),
            ("Copy All Data", -1),  # Special case for all data
        ]

        # Add actions to menu
        menu_actions = {}
        for text, column in copy_actions:
            action = context_menu.addAction(text)
            menu_actions[action] = column

        # Show menu and handle selection
        selected_action = context_menu.exec(QCursor.pos())
        if selected_action in menu_actions:
            self._handle_context_menu_action(
                row, menu_actions[selected_action])

    def _handle_context_menu_action(self, row: int, column: Any) -> None:
        """
        Handle context menu action selection.

        Args:
            row: Selected table row
            column: Column index (-1 for all data)
        """
        # Get table item data
        row_data = self._get_table_row_data(row)

        if column == -1:  # Copy all data
            self._copy_all_native_data(row_data)
        else:
            self._copy_single_field(row_data, column)

    def _get_table_row_data(self, row: int) -> Dict[str, str]:
        """Get data from a table row."""
        items = [self.natives_table.item(row, col) for col in range(5)]
        return {
            'hash': items[0].text() if items[0] else "",
            'addr': items[1].text() if items[1] else "",
            'func_name': items[2].text() if items[2] else "",
            'native_name': items[3].text() if items[3] else "",
            'namespace': items[4].text() if items[4] else "",
        }

    def _copy_single_field(self, row_data: Dict[str, str], column: int) -> None:
        """Copy a single field to clipboard."""
        field_map = {
            0: ('hash', 'hash'),
            1: ('addr', 'address'),
            2: ('func_name', 'function name'),
            3: ('native_name', 'native name'),
            4: ('namespace', 'native namespace'),
        }

        if column in field_map:
            field_key, display_name = field_map[column]
            value = row_data[field_key]

            # Always allow copying hash, addr, func_name
            if value or column in [0, 1, 2]:
                self.clipboard.setText(value)
                self.show_status_message(f"Copied {display_name}: {value}")
            else:
                self.show_status_message(
                    f"{display_name.title()} is empty", error=True)

    def _copy_all_native_data(self, row_data: Dict[str, str]) -> None:
        """Copy all native data to clipboard in formatted text."""
        all_data = (
            f"Hash: {row_data['hash']}\n"
            f"Address: {row_data['addr']}\n"
            f"Function Name: {row_data['func_name']}\n"
            f"Native Name: {row_data['native_name'] or '<None>'}\n"
            f"Native Namespace: {row_data['namespace'] or '<None>'}"
        )
        self.clipboard.setText(all_data)
        self.show_status_message("Copied all native data")

    def refresh_natives(self) -> None:
        """Refresh the natives data from the current data source."""
        if self.current_db_path:
            self.database.load_natives_from_db()
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

                reply_yes = UIHelpers.show_confirmation_dialog(
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

                reply_yes = UIHelpers.show_confirmation_dialog(
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
                        UIHelpers.show_info_message(
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


class NativeViewerDatabase:
    """
    Database operations handler for Native Viewer.

    This class manages SQLite database operations for saving and loading
    native function data, providing a persistent storage solution.
    """

    def __init__(self, parent: 'NativeViewerUI'):
        self.parent: 'NativeViewerUI' = parent

    def browse_db_file(self) -> Optional[str]:
        """
        Open file dialog to select SQLite database file.

        Returns:
            Optional[str]: Selected file path, or None if cancelled
        """
        try:
            if not self.parent:
                print("Error: Parent UI reference is None")
                return None

            # Get default path from settings
            default_path = str(self.parent.settings.value(
                "last_db_path",
                os.path.expanduser(f"~/{DEFAULT_DATABASE_NAME}")
            ))

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
            error_msg = f"Error selecting database file: {str(e)}"
            print(f"Error in browse_db_file: {str(e)}")
            if self.parent:
                self.parent.show_status_message(error_msg, error=True)
            return None

    def save_natives_to_db(
        self,
        natives: List[Dict[str, Any]],
        db_path: Optional[str] = None,
        register_native_name: Optional[str] = None
    ) -> bool:
        """
        Save native functions to SQLite database.

        Args:
            natives: List of native function data dictionaries
            db_path: Optional database file path (uses UI input if not provided)
            register_native_name: Optional register function name for metadata

        Returns:
            bool: True if save operation was successful
        """
        # Validate inputs
        if not self._validate_save_inputs(natives, db_path):
            return False

        db_path = self._get_save_db_path(db_path)
        if not db_path:
            return False

        # Check for file overwrite
        if not self._check_file_overwrite(db_path):
            return False

        # Perform save operation
        return self._perform_database_save(natives, db_path, register_native_name)

    def _validate_save_inputs(
        self,
        natives: List[Dict[str, Any]],
        db_path: Optional[str]
    ) -> bool:
        """Validate inputs for save operation."""
        if not natives:
            if self.parent:
                UIHelpers.show_warning_message(
                    self.parent,
                    "No Data",
                    "No native functions to save. Please load natives first."
                )
            return False
        return True

    def _get_save_db_path(self, db_path: Optional[str]) -> Optional[str]:
        """Get the database path for save operation."""
        if db_path is None and self.parent:
            db_path = self.parent.db_file_path.text().strip()

        if not db_path:
            if self.parent:
                UIHelpers.show_warning_message(
                    self.parent,
                    "No Database File",
                    "Please specify a database file path."
                )
            return None

        return str(db_path)

    def _check_file_overwrite(self, db_path: str) -> bool:
        """Check if user wants to overwrite existing file."""
        if os.path.exists(db_path) and self.parent:
            return UIHelpers.show_confirmation_dialog(
                self.parent,
                "File Exists",
                f"The file {os.path.basename(db_path)} already exists. "
                "Do you want to overwrite it?",
                default_yes=False,
            )
        return True

    def _perform_database_save(
        self,
        natives: List[Dict[str, Any]],
        db_path: str,
        register_native_name: Optional[str]
    ) -> bool:
        """Perform the actual database save operation."""
        conn = None
        try:
            # Setup progress dialog
            progress = None
            if self.parent:
                progress = UIHelpers.create_progress_dialog(
                    self.parent,
                    "Saving to Database",
                    "Saving natives to database...",
                    len(natives)
                )

            # Connect to database and create schema
            conn = sqlite3.connect(db_path)
            self._create_database_schema(conn)

            # Save data with transaction
            if not self._save_natives_with_transaction(
                conn, natives, register_native_name, progress
            ):
                return False

            # Finalize save operation
            self._finalize_save_operation(db_path, len(natives))
            return True

        except sqlite3.Error as e:
            return self._handle_database_error(conn, e)
        except Exception as e:
            return self._handle_general_error(e)

    def _create_database_schema(self, conn: sqlite3.Connection) -> None:
        """Create database tables if they don't exist."""
        cursor = conn.cursor()

        # Create natives table
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

        # Create metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

    def _save_natives_with_transaction(
        self,
        conn: sqlite3.Connection,
        natives: List[Dict[str, Any]],
        register_native_name: Optional[str],
        progress: Optional[QProgressDialog]
    ) -> bool:
        """Save natives data within a database transaction."""
        cursor = conn.cursor()

        # Start transaction
        conn.isolation_level = None
        conn.execute("BEGIN")

        try:
            # Save metadata
            timestamp = datetime.datetime.now().isoformat()
            self._save_metadata(cursor, timestamp, register_native_name)

            # Save natives data
            for i, native in enumerate(natives):
                if progress and progress.wasCanceled():
                    conn.rollback()
                    if self.parent:
                        self.parent.show_status_message("Operation cancelled")
                    return False

                self._save_single_native(cursor, native, timestamp)

                if progress:
                    progress.setValue(i + 1)

            conn.commit()
            return True

        except Exception as e:
            conn.rollback()
            raise e

    def _save_metadata(
        self,
        cursor: sqlite3.Cursor,
        timestamp: str,
        register_native_name: Optional[str]
    ) -> None:
        """Save metadata to the database."""
        cursor.execute(
            "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
            ("timestamp", timestamp)
        )
        cursor.execute(
            "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
            ("source", "RDR2 Native Viewer")
        )

        if register_native_name is None and self.parent:
            register_native_name = str(self.parent.register_native_name)

        if register_native_name:
            cursor.execute(
                "INSERT OR REPLACE INTO metadata VALUES (?, ?)",
                ("register_native_name", register_native_name)
            )

    def _save_single_native(
        self,
        cursor: sqlite3.Cursor,
        native: Dict[str, Any],
        timestamp: str
    ) -> None:
        """Save a single native function entry to the database."""
        cursor.execute(
            "INSERT OR REPLACE INTO natives VALUES (?, ?, ?, ?, ?, ?)",
            (
                native['hex_hash'],
                native['hex_addr'],
                native['name'],
                native.get('native_name', ''),
                native.get('namespace', ''),
                timestamp
            )
        )

    def _finalize_save_operation(self, db_path: str, count: int) -> None:
        """Finalize successful save operation."""
        if self.parent:
            db_filename = os.path.basename(db_path)
            self.parent.show_status_message(
                f"Successfully saved {count} natives to {db_filename}"
            )
            self.parent.settings.setValue("last_db_path", db_path)

    def _handle_database_error(
        self,
        conn: Optional[sqlite3.Connection],
        error: sqlite3.Error
    ) -> bool:
        """Handle database-specific errors."""
        try:
            if conn is not None:
                conn.rollback()
                conn.close()
        except:
            pass  # Connection might already be closed

        if self.parent:
            UIHelpers.show_error_message(
                self.parent,
                "Database Error",
                f"A database error occurred: {str(error)}"
            )
            self.parent.show_status_message(f"Error: {str(error)}")

        print(f"Database error: {str(error)}")
        return False

    def _handle_general_error(self, error: Exception) -> bool:
        """Handle general exceptions."""
        if self.parent:
            UIHelpers.show_error_message(
                self.parent,
                "Error",
                f"An error occurred: {str(error)}"
            )
            self.parent.show_status_message(f"Error: {str(error)}")
        return False

    def load_natives_from_db(self, db_path: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
        """
        Load native functions from SQLite database.

        Args:
            db_path: Optional database file path (uses UI input if not provided)

        Returns:
            Optional[List[Dict[str, Any]]]: List of loaded natives, or None if failed
        """
        # Get and validate database path
        db_path = self._get_load_db_path(db_path)
        if not db_path:
            return None

        # Validate database file
        if not self._validate_database_file(db_path):
            return None

        # Load from database
        return self._load_from_database_file(db_path)

    def _get_load_db_path(self, db_path: Optional[str]) -> Optional[str]:
        """Get and validate the database path for load operation."""
        if db_path is None and self.parent:
            db_path = self.parent.db_file_path.text().strip()
            if not db_path:
                db_path = str(self.parent.settings.value("last_db_path", ""))
                if db_path:
                    self.parent.db_file_path.setText(db_path)
                else:
                    UIHelpers.show_warning_message(
                        self.parent,
                        "No Database File",
                        "Please specify a database file path."
                    )
                    return None

        if not db_path:
            print("Error: No database path provided")
            return None

        return db_path

    def _validate_database_file(self, db_path: str) -> bool:
        """Validate that the database file exists and is valid."""
        if not os.path.exists(db_path):
            if self.parent:
                UIHelpers.show_warning_message(
                    self.parent,
                    "File Not Found",
                    f"The database file {db_path} does not exist."
                )
            return False
        return True

    def _load_from_database_file(self, db_path: str) -> Optional[List[Dict[str, Any]]]:
        """Load natives from the specified database file."""
        conn = None
        try:
            conn = sqlite3.connect(db_path)

            # Validate database schema
            if not self._validate_database_schema(conn):
                conn.close()
                return None

            # Get user confirmation with metadata
            if not self._get_load_confirmation(conn, db_path):
                conn.close()
                return None

            # Load the natives data
            natives = self._load_natives_data(conn, db_path)
            conn.close()

            return natives

        except sqlite3.Error as e:
            self._handle_load_database_error(conn, e)
            return None
        except Exception as e:
            self._handle_load_general_error(e)
            return None

    def _validate_database_schema(self, conn: sqlite3.Connection) -> bool:
        """Validate that the database contains the required tables."""
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='natives'"
        )
        if not cursor.fetchone():
            if self.parent:
                UIHelpers.show_warning_message(
                    self.parent,
                    "Invalid Database",
                    "This database does not contain a natives table."
                )
            return False
        return True

    def _get_load_confirmation(self, conn: sqlite3.Connection, db_path: str) -> bool:
        """Get user confirmation to load from database."""
        if not self.parent:
            return True

        # Get metadata for confirmation dialog
        metadata_str = self._get_database_metadata(conn)
        db_filename = os.path.basename(db_path)

        return UIHelpers.show_confirmation_dialog(
            self.parent,
            "Load Natives",
            f"Load natives from {db_filename}?\n\n"
            f"Database Information:\n{metadata_str}",
            default_yes=True
        )

    def _get_database_metadata(self, conn: sqlite3.Connection) -> str:
        """Get database metadata as a formatted string."""
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM metadata")
            metadata = dict(cursor.fetchall())
            return "\n".join(f"{k}: {v}" for k, v in metadata.items())
        except sqlite3.Error:
            return "No metadata available"

    def _load_natives_data(self, conn: sqlite3.Connection, db_path: str) -> List[Dict[str, Any]]:
        """Load natives data from database connection."""
        cursor = conn.cursor()

        # Get total count for progress
        cursor.execute("SELECT COUNT(*) FROM natives")
        total_natives = cursor.fetchone()[0]

        # Setup progress dialog
        progress = None
        if self.parent:
            progress = UIHelpers.create_progress_dialog(
                self.parent,
                "Loading from Database",
                "Loading natives from database...",
                total_natives
            )

        # Check schema and load data
        has_extended_schema = self._check_extended_schema(cursor)
        natives = self._extract_natives_from_database(
            cursor, has_extended_schema, progress)

        # Update UI if successful
        if self.parent and natives:
            self._finalize_load_operation(db_path, natives)

        return natives

    def _check_extended_schema(self, cursor: sqlite3.Cursor) -> bool:
        """Check if database has extended schema with native_name and namespace."""
        cursor.execute("PRAGMA table_info(natives)")
        columns = {column_info[1] for column_info in cursor.fetchall()}
        return 'native_name' in columns and 'namespace' in columns

    def _extract_natives_from_database(
        self,
        cursor: sqlite3.Cursor,
        has_extended_schema: bool,
        progress: Optional[QProgressDialog]
    ) -> List[Dict[str, Any]]:
        """Extract natives data from database cursor."""
        natives: List[Dict[str, Any]] = []

        # Select appropriate query based on schema
        query = (
            "SELECT hash, address, name, native_name, namespace FROM natives"
            if has_extended_schema
            else "SELECT hash, address, name FROM natives"
        )
        cursor.execute(query)

        for i, row in enumerate(cursor.fetchall()):
            if progress and progress.wasCanceled():
                if self.parent:
                    self.parent.show_status_message("Operation cancelled")
                return []

            native_entry = self._create_native_entry_from_row(
                row, has_extended_schema)
            natives.append(native_entry)

            if progress:
                progress.setValue(i + 1)

        return natives

    def _create_native_entry_from_row(
        self,
        row: tuple[str, ...],
        has_extended_schema: bool
    ) -> Dict[str, Any]:
        """Create a native entry dictionary from database row."""
        if has_extended_schema:
            hash_val, addr, name, native_name, namespace = row
        else:
            hash_val, addr, name = row
            native_name = ""
            namespace = ""

        # Convert string values to integers
        int_hash = int(hash_val, 16) if hash_val.startswith(
            '0x') else int(hash_val)
        int_addr = int(addr, 16) if addr.startswith('0x') else int(addr)

        native_entry: Dict[str, Any] = {
            'hash': int_hash,
            'hex_hash': hash_val,
            'addr': int_addr,
            'hex_addr': addr,
            'name': name,
            'native_name': native_name,
            'namespace': namespace
        }

        # Generate search string
        native_entry['search_string'] = self._generate_search_string_for_native(
            native_entry)
        return native_entry

    def _generate_search_string_for_native(self, native: Dict[str, Any]) -> str:
        """Generate search string for a native entry."""
        search_fields = [
            native.get('hex_hash', ''),
            native.get('hex_addr', ''),
            native.get('name', ''),
            native.get('native_name', ''),
            native.get('namespace', ''),
        ]
        return ' '.join(field.lower() for field in search_fields)

    def _finalize_load_operation(self, db_path: str, natives: List[Dict[str, Any]]) -> None:
        """Finalize successful load operation and update UI."""
        db_filename = os.path.basename(db_path)

        # Update main UI
        self.parent.natives = natives
        self.parent.update_table()
        self.parent.update_natives_count_display(len(natives), len(natives))

        # Update status and search placeholder
        self.parent.show_status_message(
            f"Successfully loaded {len(natives)} natives from {db_filename}"
        )
        self.parent.search_box.setPlaceholderText(
            f"Search {len(natives)} loaded natives..."
        )
        self.parent.current_db_path = db_path

    def _handle_load_database_error(
        self,
        conn: Optional[sqlite3.Connection],
        error: sqlite3.Error
    ) -> None:
        """Handle database errors during load operation."""
        try:
            if conn is not None:
                conn.close()
        except:
            pass

        if self.parent:
            UIHelpers.show_error_message(
                self.parent,
                "Database Error",
                f"A database error occurred: {str(error)}"
            )
            self.parent.show_status_message(f"Error: {str(error)}")
        print(f"Database error: {str(error)}")

    def _handle_load_general_error(self, error: Exception) -> None:
        """Handle general errors during load operation."""
        if self.parent:
            UIHelpers.show_error_message(
                self.parent,
                "Error",
                f"An error occurred: {str(error)}"
            )
            self.parent.show_status_message(f"Error: {str(error)}")


def run() -> Optional['NativeViewerUI']:
    """
    Main entry point for the Native Viewer application.

    This function initializes the Qt application and creates the main window.
    It handles the application lifecycle and ensures proper cleanup.

    Returns:
        Optional[NativeViewerUI]: The main window instance, or None if failed
    """
    global _native_viewer_window
    print("RDR2 Native Viewer")
    print("------------------")

    try:
        # Get or create QApplication instance
        app = QApplication.instance() or QApplication([])

        if isinstance(app, QApplication):
            # Create and show main window
            window = NativeViewerUI(app.clipboard())
            window.show()
            window.activateWindow()
            window.raise_()

            # Start event loop
            app.exec()

            # Store reference for potential future use
            _native_viewer_window = window
            return window
        else:
            print("Error: Could not get QApplication instance")
            return None

    except Exception as e:
        print(f"Error running UI: {str(e)}")
        return None


# Global window reference for potential external access
_native_viewer_window: Optional['NativeViewerUI'] = None


if __name__ == "__main__":
    run()
