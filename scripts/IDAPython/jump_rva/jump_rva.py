import idaapi
import idc
import ida_kernwin
import ida_netnode
import json
from PyQt5 import QtWidgets, QtCore, QtGui

# Use a simpler approach with NetNode API
NETNODE_NAME = "$ jump_rva_history"
history = []


class JumpToRVAPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Jump to RVA by entering RVA (hex or decimal)"
    help = "Jump to address by RVA: (ImageBase +) RVA"
    wanted_name = "Jump to RVA"
    wanted_hotkey = "Shift-G"

    def __init__(self):
        self.netnode = None

    def init(self):
        # Initialize the netnode correctly
        self.netnode = ida_netnode.netnode(NETNODE_NAME, 0, True)
        self.load_history()
        return idaapi.PLUGIN_OK

    def load_history(self):
        """Load history from netnode using supval instead of hashval"""
        global history
        try:
            # Use supval(0) instead of hashval_str
            history_data = self.netnode.supstr(0)
            if history_data:
                history = json.loads(history_data)
            else:
                history = []
        except Exception as e:
            print(f"[JumpToRVAPlugin] Error loading history: {e}")
            history = []

    def save_history(self):
        """Save history to netnode using supval instead of hashval"""
        try:
            # Use supset(0) instead of hashval_str
            self.netnode.supset(0, json.dumps(history))
        except Exception as e:
            print(f"[JumpToRVAPlugin] Error saving history: {e}")

    def run(self, arg):
        rva_input, ok = self.show_rva_input_dialog()

        if not ok:
            return

        try:
            rva = int(rva_input, 0)
        except ValueError:
            ida_kernwin.msg("[JumpToRVAPlugin] Invalid input: not a number.\n")
            return

        base = idaapi.get_imagebase()
        target = base + rva

        if not idc.jumpto(target):
            ida_kernwin.msg(f"[JumpToRVAPlugin] Address 0x{target:X} is not valid.\n")
        self.add_to_history(rva_input)

    def show_rva_input_dialog(self):
        dialog = QtWidgets.QDialog()
        dialog.setWindowTitle("Jump to RVA")

        # Set information icon (blue "i") as the window icon
        dialog.setWindowIcon(
            QtGui.QIcon(QtWidgets.QApplication.style().standardIcon(QtWidgets.QStyle.SP_MessageBoxInformation)))

        # Remove the question mark button from the title bar
        dialog.setWindowFlags(dialog.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)

        # Create main layout
        main_layout = QtWidgets.QVBoxLayout(dialog)

        # Create form layout for the input field
        form_layout = QtWidgets.QFormLayout()

        # Create combo box
        combo_box = QtWidgets.QComboBox(dialog)
        combo_box.setEditable(True)
        combo_box.setInsertPolicy(QtWidgets.QComboBox.NoInsert)  # Prevent adding new items automatically

        # Add history items if available
        if history:
            combo_box.addItems(history)
            combo_box.clearEditText()

            # Setup completer for better navigation
            line_edit = combo_box.lineEdit()
            completer = QtWidgets.QCompleter(history, combo_box)
            completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
            completer.setCompletionMode(QtWidgets.QCompleter.PopupCompletion)
            line_edit.setCompleter(completer)

        # Add label and combo box to form layout
        form_layout.addRow("RVA", combo_box)

        # Add form layout to main layout
        main_layout.addLayout(form_layout)

        # Create button layout
        button_layout = QtWidgets.QHBoxLayout()

        # Create buttons
        ok_button = QtWidgets.QPushButton("OK", dialog)
        cancel_button = QtWidgets.QPushButton("Cancel", dialog)
        help_button = QtWidgets.QPushButton("Help", dialog)

        # Connect buttons to actions
        ok_button.clicked.connect(dialog.accept)
        cancel_button.clicked.connect(dialog.reject)
        help_button.clicked.connect(self.show_help)

        # Add buttons to button layout
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(help_button)

        # Add button layout to main layout
        main_layout.addLayout(button_layout)

        # Set dialog size
        dialog.setFixedSize(300, 100)

        # Execute dialog
        ok = dialog.exec_() == QtWidgets.QDialog.Accepted

        # Get input value
        rva_input = combo_box.currentText()

        return rva_input, ok

    def show_help(self):
        """Display help information"""
        help_text = "Enter an RVA value (hex or decimal) to jump to"
        QtWidgets.QMessageBox.information(None, "Jump to RVA Help", help_text)

    def add_to_history(self, rva_input):
        global history

        if rva_input in history:
            history.remove(rva_input)  # Remove if exists to avoid duplicates

        history.insert(0, rva_input)  # Add to beginning for easier access

        if len(history) > 50:
            history = history[:50]  # Keep only the 10 most recent entries

        self.save_history()  # Save history after each update

    def term(self):
        self.save_history()


def PLUGIN_ENTRY():
    return JumpToRVAPlugin()