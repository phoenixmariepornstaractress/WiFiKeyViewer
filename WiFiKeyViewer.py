import ctypes
import logging
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from PyQt5.QtCore import QThread, QTimer, pyqtSignal, Qt, QPoint
from PyQt5.QtGui import QIcon, QClipboard
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
    QMessageBox, QTableWidget, QTableWidgetItem, QTabWidget, QStatusBar,
    QProgressDialog, QMenu, QAction, QFileDialog, QWidget, QCheckBox
)
import qrcode
import shutil
import pandas as pd
import openpyxl

# Configuration
class Config:
    LOG_FILE = "app_error_log.txt"
    BACKUP_DIR = "wifi_backups"
    TEMP_PROFILE_PREFIX = "temp_profile_"
    NETSH_TIMEOUT = 10  # Seconds
    AUTO_REFRESH_INTERVAL = 300000  # Milliseconds (5 minutes)
    VALID_PROFILE_REGEX = r'^[\w\s\-\.]+$'
    SUPPORTED_AUTH_TYPES = {"WPA2PSK", "WPAPSK", "open"}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(Config.LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class WifiProfileError(Exception):
    """Custom exception for Wi-Fi profile operations."""
    pass

class NetworkManager:
    """Manages Wi-Fi network operations using netsh commands."""
    
    def __init__(self):
        self._cache = {}  # Cache for profile details

    @staticmethod
    def run_netsh_command(args: List[str], timeout: int = Config.NETSH_TIMEOUT) -> str:
        """Executes a netsh command with error handling."""
        try:
            return subprocess.check_output(
                ["netsh"] + args,
                encoding="utf-8",
                stderr=subprocess.STDOUT,
                timeout=timeout
            )
        except subprocess.TimeoutExpired:
            raise WifiProfileError(f"Command '{' '.join(args)}' timed out after {timeout} seconds")
        except subprocess.CalledProcessError as e:
            raise WifiProfileError(f"Command failed: {e.output.strip()}")
        except Exception as e:
            raise WifiProfileError(f"Unexpected error: {str(e)}")

    def extract_wifi_profiles(self) -> List[Tuple[str, Dict[str, str]]]:
        """Extracts all Wi-Fi profiles and their details."""
        output = self.run_netsh_command(["wlan", "show", "profiles"])
        profiles = [
            line.split(":")[1].strip()
            for line in output.splitlines() if "All User Profile" in line
        ]
        extracted_data = []
        for profile in profiles:
            if not self._is_valid_profile_name(profile):
                logger.warning(f"Invalid profile name skipped: {profile}")
                continue
            details = self.get_profile_details(profile)
            extracted_data.append((profile, details))
        return extracted_data

    def get_profile_details(self, profile_name: str) -> Dict[str, str]:
        """Retrieves detailed information for a Wi-Fi profile."""
        if profile_name in self._cache:
            return self._cache[profile_name]
        
        details = {
            "password": "No Password",
            "auth": "N/A",
            "encryption": "N/A",
            "ssid_visibility": "N/A",
            "status": "Disconnected",
            "strength": "N/A"
        }
        try:
            output = self.run_netsh_command(
                ["wlan", "show", "profile", profile_name, "key=clear"]
            )
            for line in output.splitlines():
                if "Key Content" in line:
                    password = line.split(":")[1].strip()
                    details["password"] = password
                    details["strength"] = self._check_password_strength(password)
                elif "Authentication" in line:
                    details["auth"] = line.split(":")[1].strip()
                elif "Cipher" in line:
                    details["encryption"] = line.split(":")[1].strip()
                elif "SSID name" in line and "broadcast" in line:
                    details["ssid_visibility"] = line.split(":")[1].strip()

            connected_output = self.run_netsh_command(["wlan", "show", "interfaces"])
            if profile_name in connected_output:
                details["status"] = "Connected"
            self._cache[profile_name] = details
        except WifiProfileError as e:
            logger.error(f"Error getting details for {profile_name}: {e}")
            details["password"] = "Access Denied (Run as Administrator)"
        return details

    def scan_available_networks(self) -> List[Dict[str, str]]:
        """Scans for available Wi-Fi networks."""
        output = self.run_netsh_command(["wlan", "show", "networks", "mode=bssid"])
        networks = []
        current_network = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID"):
                if current_network:
                    networks.append(current_network)
                current_network = {"SSID": line.split(":", 1)[1].strip().strip('"')}
            elif "Signal" in line:
                current_network["Signal"] = line.split(":", 1)[1].strip()
            elif "Authentication" in line:
                current_network["Authentication"] = line.split(":", 1)[1].strip()
            elif "Encryption" in line:
                current_network["Encryption"] = line.split(":", 1)[1].strip()
            elif "BSSID" in line:
                current_network["BSSID"] = line.split(":", 1)[1].strip()
        if current_network:
            networks.append(current_network)
        return networks

    def connect_to_profile(self, profile_name: str) -> None:
        """Connects to a saved Wi-Fi profile."""
        if not self._is_valid_profile_name(profile_name):
            raise WifiProfileError(f"Invalid profile name: {profile_name}")
        self.run_netsh_command(["wlan", "connect", f"name=\"{profile_name}\""])

    def disconnect(self) -> None:
        """Disconnects from the current Wi-Fi network."""
        self.run_netsh_command(["wlan", "disconnect"])

    def delete_profile(self, profile_name: str) -> None:
        """Deletes a Wi-Fi profile."""
        if not self._is_valid_profile_name(profile_name):
            raise WifiProfileError(f"Invalid profile name: {profile_name}")
        self.run_netsh_command(["wlan", "delete", "profile", f"name=\"{profile_name}\""])
        if profile_name in self._cache:
            del self._cache[profile_name]

    def _check_password_strength(self, password: str) -> str:
        """Evaluates password strength."""
        if not password or password == "No Password":
            return "N/A"
        score = sum([
            len(password) >= 8,
            bool(re.search(r"[a-z]", password)),
            bool(re.search(r"[A-Z]", password)),
            bool(re.search(r"\d", password)),
            bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
        ])
        strength_map = {5: "Very Strong", 4: "Strong", 3: "Moderate", 2: "Weak", 1: "Very Weak"}
        return strength_map.get(score, "Very Weak")

    def _is_valid_profile_name(self, name: str) -> bool:
        """Validates profile name to prevent command injection."""
        return bool(re.match(Config.VALID_PROFILE_REGEX, name))

class FileManager:
    """Handles file operations for export, import, and backups."""
    
    def export_to_text(self, data: List[Tuple[str, Dict[str, str]]], path: str) -> None:
        """Exports profile data to a text file."""
        with open(path, "w", encoding="utf-8") as f:
            for profile, details in data:
                f.write(f"Profile: {profile}, Password: {details['password']}, "
                        f"Auth: {details['auth']}, Encryption: {details['encryption']}\n")

    def export_to_excel(self, data: List[Tuple[str, Dict[str, str]]], path: str) -> None:
        """Exports profile data to an Excel file."""
        df = pd.DataFrame([
            {"Profile Name": profile, **details}
            for profile, details in data
        ])
        df.to_excel(path, index=False, engine="openpyxl")

    def backup_logs(self, log_file: str, backup_dir: str = Config.BACKUP_DIR) -> str:
        """Creates a timestamped backup of the log file."""
        if not os.path.exists(log_file):
            raise WifiProfileError("Log file does not exist")
        os.makedirs(backup_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f"log_backup_{timestamp}.txt")
        shutil.copy2(log_file, backup_path)
        return backup_path

    def generate_qr_code(self, profile: str, password: str, path: str) -> None:
        """Generates a QR code for Wi-Fi credentials."""
        if password in ("No Password", "Access Denied (Run as Administrator)"):
            raise WifiProfileError("Cannot generate QR code without valid password")
        qr_data = f"WIFI:S:{profile};T:WPA;P:{password};;"
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(qr_data)
        qr.make(fit=True)
        qr.make_image(fill_color="black", back_color="white").save(path)

class Worker(QThread):
    """Worker thread for long-running operations."""
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

class WifiProfileExtractor(QMainWindow):
    """Main application window for Wi-Fi profile management."""
    
    def __init__(self, network_manager: NetworkManager = None, file_manager: FileManager = None):
        super().__init__()
        self.network_manager = network_manager or NetworkManager()
        self.file_manager = file_manager or FileManager()
        self.setWindowTitle("Wi-Fi Profile Management App")
        self.setGeometry(100, 100, 1300, 800)
        self.show_passwords = False
        self.profile_data: List[Tuple[str, Dict[str, str]]] = []
        self.init_ui()
        self.check_admin_privileges()
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")

        # Setup auto-refresh timer
        self.auto_refresh_timer = QTimer(self)
        self.auto_refresh_timer.timeout.connect(self.extract_wifi_profiles)
        # self.auto_refresh_timer.start(Config.AUTO_REFRESH_INTERVAL)

    def init_ui(self):
        """Initializes the user interface elements."""
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        main_layout = QVBoxLayout(self.central_widget)

        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # Saved Profiles Tab
        self.saved_profiles_tab = QWidget()
        self.setup_saved_profiles_tab(self.saved_profiles_tab)
        self.tab_widget.addTab(self.saved_profiles_tab, "Saved Profiles")

        # Available Networks Tab
        self.available_networks_tab = QWidget()
        self.setup_available_networks_tab(self.available_networks_tab)
        self.tab_widget.addTab(self.available_networks_tab, "Available Networks")

    def setup_saved_profiles_tab(self, tab_widget: QWidget):
        """Sets up the UI for the Saved Profiles tab."""
        layout = QVBoxLayout(tab_widget)

        # Search box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search Wi-Fi Profile (e.g., HomeWiFi)")
        self.search_box.textChanged.connect(self.search_profiles)
        self.search_box.setToolTip("Enter profile name to filter results")
        layout.addWidget(self.search_box)

        # Password toggle
        password_layout = QHBoxLayout()
        self.show_password_toggle = QCheckBox("Show Passwords")
        self.show_password_toggle.stateChanged.connect(self.toggle_password_visibility)
        password_layout.addWidget(self.show_password_toggle)
        password_layout.addStretch()
        layout.addLayout(password_layout)

        # Table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Profile Name", "Password", "Authentication", "Encryption", "SSID Visibility", "Status", "Strength"]
        )
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.setStyleSheet("QTableWidget::item { padding: 5px; }")
        self.table.setAlternatingRowColors(True)
        self.table.setToolTip("Right-click for actions; double-click to connect")
        layout.addWidget(self.table)

        self.setup_buttons(layout)
        self.table.itemSelectionChanged.connect(self.update_button_states)

    def setup_available_networks_tab(self, tab_widget: QWidget):
        """Sets up the UI for the Available Networks tab."""
        layout = QVBoxLayout(tab_widget)

        self.available_networks_table = QTableWidget(0, 5)
        self.available_networks_table.setHorizontalHeaderLabels(
            ["SSID", "Signal (dBm)", "Authentication", "Encryption", "BSSID"]
        )
        self.available_networks_table.setSortingEnabled(True)
        self.available_networks_table.horizontalHeader().setStretchLastSection(True)
        self.available_networks_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.available_networks_table.setSelectionMode(QTableWidget.SingleSelection)
        layout.addWidget(self.available_networks_table)

        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Scan Networks")
        self.scan_button.clicked.connect(self.scan_available_networks)
        self.scan_button.setToolTip("Scan for available Wi-Fi networks")
        button_layout.addWidget(self.scan_button)

        self.connect_available_button = QPushButton("Connect to Network")
        self.connect_available_button.clicked.connect(self.connect_to_available_network)
        self.connect_available_button.setEnabled(False)
        self.connect_available_button.setToolTip("Connect to the selected network")
        button_layout.addWidget(self.connect_available_button)
        layout.addLayout(button_layout)

        self.available_networks_table.itemSelectionChanged.connect(
            lambda: self.connect_available_button.setEnabled(self.available_networks_table.currentRow() != -1)
        )

    def setup_buttons(self, layout: QVBoxLayout):
        """Sets up action buttons."""
        button_layout = QHBoxLayout()

        self.extract_button = QPushButton("Extract Profiles")
        self.extract_button.clicked.connect(self.extract_wifi_profiles)
        self.extract_button.setToolTip("Extract all saved Wi-Fi profiles")
        button_layout.addWidget(self.extract_button)

        self.export_text_button = QPushButton("Export to Text")
        self.export_text_button.clicked.connect(self.export_to_text)
        self.export_text_button.setEnabled(False)
        self.export_text_button.setToolTip("Export profiles to a text file")
        button_layout.addWidget(self.export_text_button)

        self.export_excel_button = QPushButton("Export to Excel")
        self.export_excel_button.clicked.connect(self.export_to_excel)
        self.export_excel_button.setEnabled(False)
        self.export_excel_button.setToolTip("Export profiles to an Excel file")
        button_layout.addWidget(self.export_excel_button)

        self.qr_button = QPushButton("Generate QR Code")
        self.qr_button.clicked.connect(self.generate_qr_code)
        self.qr_button.setEnabled(False)
        self.qr_button.setToolTip("Generate QR code for selected profile")
        button_layout.addWidget(self.qr_button)

        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.connect_to_profile)
        self.connect_button.setEnabled(False)
        self.connect_button.setToolTip("Connect to the selected profile")
        button_layout.addWidget(self.connect_button)

        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.clicked.connect(self.disconnect)
        self.disconnect_button.setToolTip("Disconnect from the current network")
        button_layout.addWidget(self.disconnect_button)

        self.delete_button = QPushButton("Delete Profile")
        self.delete_button.clicked.connect(self.delete_profile)
        self.delete_button.setEnabled(False)
        self.delete_button.setToolTip("Delete the selected profile")
        button_layout.addWidget(self.delete_button)

        layout.addLayout(button_layout)

    def update_button_states(self):
        """Updates button states based on selection and data."""
        has_selection = self.table.currentRow() != -1
        has_data = self.table.rowCount() > 0
        self.export_text_button.setEnabled(has_data)
        self.export_excel_button.setEnabled(has_data)
        self.qr_button.setEnabled(has_selection)
        self.connect_button.setEnabled(has_selection)
        self.delete_button.setEnabled(has_selection)

    def show_context_menu(self, position: QPoint):
        """Displays a context menu for the table."""
        if self.table.currentRow() == -1:
            return
        menu = QMenu(self)
        copy_action = QAction("Copy Profile Info", self)
        copy_action.triggered.connect(self.copy_to_clipboard)
        menu.addAction(copy_action)
        connect_action = QAction("Connect", self)
        connect_action.triggered.connect(self.connect_to_profile)
        menu.addAction(connect_action)
        delete_action = QAction("Delete", self)
        delete_action.triggered.connect(self.delete_profile)
        menu.addAction(delete_action)
        menu.exec_(self.table.viewport().mapToGlobal(position))

    def toggle_password_visibility(self):
        """Toggles password visibility in the table."""
        self.show_passwords = self.show_password_toggle.isChecked()
        self._refresh_table()

    def extract_wifi_profiles(self):
        """Extracts Wi-Fi profiles in a background thread."""
        self.statusBar.showMessage("Extracting Wi-Fi profiles...")
        self.progress_dialog = QProgressDialog("Extracting profiles...", None, 0, 0, self)
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.show()

        worker = Worker(self.network_manager.extract_wifi_profiles)
        worker.finished.connect(self._handle_extraction_finished)
        worker.error.connect(self._handle_extraction_error)
        worker.start()

    def _handle_extraction_finished(self, extracted_data: List[Tuple[str, Dict[str, str]]]):
        """Populates the table with extracted profile data."""
        self.profile_data = extracted_data
        self._refresh_table()
        self.progress_dialog.close()
        self.update_button_states()
        self.statusBar.showMessage(f"Extracted {len(extracted_data)} Wi-Fi profiles.", 3000)

    def _handle_extraction_error(self, error_message: str):
        """Handles errors during profile extraction."""
        self.progress_dialog.close()
        logger.error(f"Profile extraction failed: {error_message}")
        QMessageBox.critical(self, "Error", f"Failed to extract profiles: {error_message}")
        self.statusBar.showMessage("Failed to extract profiles.", 5000)

    def _refresh_table(self):
        """Refreshes the table with current profile data."""
        self.table.setRowCount(0)
        for profile, details in self.profile_data:
            row_position = self.table.rowCount()
            self.table.insertRow(row_position)
            password_display = (
                details["password"] if self.show_passwords else "****"
                if details["password"] not in ("No Password", "Access Denied (Run as Administrator)")
                else details["password"]
            )
            values = [
                profile, password_display, details["auth"], details["encryption"],
                details["ssid_visibility"], details["status"], details["strength"]
            ]
            for i, value in enumerate(values):
                item = QTableWidgetItem(value)
                if i == 1 and value == "****":
                    item.setToolTip("Check 'Show Passwords' to view")
                self.table.setItem(row_position, i, item)
        self.table.resizeColumnsToContents()

    def scan_available_networks(self):
        """Scans for available networks in a background thread."""
        self.statusBar.showMessage("Scanning available networks...")
        self.progress_dialog = QProgressDialog("Scanning networks...", None, 0, 0, self)
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.show()

        worker = Worker(self.network_manager.scan_available_networks)
        worker.finished.connect(self._handle_scan_finished)
        worker.error.connect(self._handle_scan_error)
        worker.start()

    def _handle_scan_finished(self, networks: List[Dict[str, str]]):
        """Populates the available networks table."""
        self.available_networks_table.setRowCount(0)
        for net in networks:
            row_position = self.available_networks_table.rowCount()
            self.available_networks_table.insertRow(row_position)
            values = [
                net.get("SSID", "N/A"), net.get("Signal", "N/A"),
                net.get("Authentication", "N/A"), net.get("Encryption", "N/A"),
                net.get("BSSID", "N/A")
            ]
            for i, value in enumerate(values):
                self.available_networks_table.setItem(row_position, i, QTableWidgetItem(value))
        self.available_networks_table.resizeColumnsToContents()
        self.progress_dialog.close()
        self.statusBar.showMessage(f"Found {len(networks)} available networks.", 3000)

    def _handle_scan_error(self, error_message: str):
        """Handles errors during network scanning."""
        self.progress_dialog.close()
        logger.error(f"Network scan failed: {error_message}")
        QMessageBox.critical(self, "Error", f"Failed to scan networks: {error_message}")
        self.statusBar.showMessage("Failed to scan networks.", 5000)

    def connect_to_profile(self):
        """Connects to the selected profile."""
        selected_row = self.table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "No Selection", "Please select a profile to connect to.")
            return
        profile = self.table.item(selected_row, 0).text()
        try:
            self.network_manager.connect_to_profile(profile)
            QMessageBox.information(self, "Success", f"Attempted to connect to '{profile}'.")
            self.statusBar.showMessage(f"Connected to '{profile}'.", 3000)
            self.extract_wifi_profiles()
        except WifiProfileError as e:
            logger.error(f"Failed to connect to {profile}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to connect to '{profile}': {e}")
            self.statusBar.showMessage("Connection failed.", 5000)

    def connect_to_available_network(self):
        """Connects to a selected available network."""
        selected_row = self.available_networks_table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "No Selection", "Please select a network to connect to.")
            return
        ssid = self.available_networks_table.item(selected_row, 0).text()
        auth = self.available_networks_table.item(selected_row, 2).text()
        if auth not in Config.SUPPORTED_AUTH_TYPES:
            QMessageBox.warning(self, "Unsupported", f"Authentication type '{auth}' is not supported.")
            return

        password, ok = QInputDialog.getText(
            self, "Connect to Network", f"Enter password for '{ssid}':", QLineEdit.Password
        )
        if not ok or not password:
            self.statusBar.showMessage("Connection cancelled.", 2000)
            return

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, encoding="utf-8") as temp_file:
                profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <hex>{ssid.encode('utf-8').hex()}</hex>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{auth}</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""
                temp_file.write(profile_xml)
                temp_path = temp_file.name

            self.network_manager.run_netsh_command(["wlan", "add", "profile", f"filename=\"{temp_path}\""])
            self.network_manager.connect_to_profile(ssid)
            QMessageBox.information(self, "Success", f"Attempted to connect to '{ssid}'.")
            self.statusBar.showMessage(f"Connected to '{ssid}'.", 3000)
            self.extract_wifi_profiles()
        except WifiProfileError as e:
            logger.error(f"Failed to connect to {ssid}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to connect to '{ssid}': {e}")
            self.statusBar.showMessage("Connection failed.", 5000)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def disconnect(self):
        """Disconnects from the current network."""
        reply = QMessageBox.question(
            self, "Disconnect", "Are you sure you want to disconnect from the current network?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                self.network_manager.disconnect()
                QMessageBox.information(self, "Success", "Disconnected from the current network.")
                self.statusBar.showMessage("Disconnected.", 3000)
                self.extract_wifi_profiles()
            except WifiProfileError as e:
                logger.error(f"Failed to disconnect: {e}")
                QMessageBox.critical(self, "Error", f"Failed to disconnect: {e}")
                self.statusBar.showMessage("Disconnection failed.", 5000)

    def delete_profile(self):
        """Deletes the selected profile."""
        selected_row = self.table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "No Selection", "Please select a profile to delete.")
            return
        profile = self.table.item(selected_row, 0).text()
        reply = QMessageBox.question(
            self, "Delete Profile", f"Are you sure you want to delete '{profile}'?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                self.network_manager.delete_profile(profile)
                QMessageBox.information(self, "Success", f"Profile '{profile}' deleted.")
                self.statusBar.showMessage(f"Deleted '{profile}'.", 3000)
                self.extract_wifi_profiles()
            except WifiProfileError as e:
                logger.error(f"Failed to delete {profile}: {e}")
                QMessageBox.critical(self, "Error", f"Failed to delete '{profile}': {e}")
                self.statusBar.showMessage("Deletion failed.", 5000)

    def export_to_text(self):
        """Exports profiles to a text file."""
        path, _ = QFileDialog.getSaveFileName(self, "Save to Text", "", "Text Files (*.txt);;All Files (*)")
        if path:
            try:
                self.file_manager.export_to_text(self.profile_data, path)
                QMessageBox.information(self, "Success", "Exported to text file.")
                self.statusBar.showMessage(f"Exported to {os.path.basename(path)}.", 3000)
            except WifiProfileError as e:
                logger.error(f"Failed to export to text: {e}")
                QMessageBox.critical(self, "Error", f"Failed to export to text: {e}")
                self.statusBar.showMessage("Export failed.", 5000)

    def export_to_excel(self):
        """Exports profiles to an Excel file."""
        path, _ = QFileDialog.getSaveFileName(self, "Save to Excel", "", "Excel Files (*.xlsx);;All Files (*)")
        if path:
            try:
                self.file_manager.export_to_excel(self.profile_data, path)
                QMessageBox.information(self, "Success", "Exported to Excel file.")
                self.statusBar.showMessage(f"Exported to {os.path.basename(path)}.", 3000)
            except WifiProfileError as e:
                logger.error(f"Failed to export to Excel: {e}")
                QMessageBox.critical(self, "Error", f"Failed to export to Excel: {e}")
                self.statusBar.showMessage("Export failed.", 5000)

    def generate_qr_code(self):
        """Generates a QR code for the selected profile."""
        selected_row = self.table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "No Selection", "Please select a profile for QR code.")
            return
        profile = self.table.item(selected_row, 0).text()
        password = self.profile_data[selected_row][1]["password"]
        path = f"{profile}_qr.png"
        try:
            self.file_manager.generate_qr_code(profile, password, path)
            QMessageBox.information(self, "Success", f"QR code saved as {path}.")
            self.statusBar.showMessage(f"QR code generated: {path}.", 3000)
        except WifiProfileError as e:
            logger.error(f"Failed to generate QR code: {e}")
            QMessageBox.critical(self, "Error", f"Failed to generate QR code: {e}")
            self.statusBar.showMessage("QR code generation failed.", 5000)

    def copy_to_clipboard(self):
        """Copies selected profile info to clipboard."""
        selected_row = self.table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "No Selection", "Please select a profile to copy.")
            return
        profile = self.table.item(selected_row, 0).text()
        password = self.profile_data[selected_row][1]["password"]
        clipboard = QApplication.clipboard()
        clipboard.setText(f"Profile: {profile}\nPassword: {password}")
        QMessageBox.information(self, "Success", "Profile info copied to clipboard.")
        self.statusBar.showMessage("Copied to clipboard.", 3000)

    def search_profiles(self):
        """Filters table rows based on search query."""
        query = self.search_box.text().lower()
        for row in range(self.table.rowCount()):
            profile = self.table.item(row, 0).text().lower()
            self.table.setRowHidden(row, query not in profile)
        self.statusBar.showMessage(f"Filtered profiles with query: {query or 'None'}.", 2000)

    def check_admin_privileges(self):
        """Checks for administrative privileges."""
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                QMessageBox.warning(
                    self, "Administrative Privileges",
                    "Some features require administrative privileges to function fully."
                )
                self.statusBar.showMessage("Limited functionality without admin privileges.", 5000)
        except Exception as e:
            logger.error(f"Failed to check admin privileges: {e}")
            self.statusBar.showMessage("Unable to verify admin privileges.", 5000)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WifiProfileExtractor()
    window.show()
    sys.exit(app.exec_())
