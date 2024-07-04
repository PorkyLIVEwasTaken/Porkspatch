import ctypes
import os
import string
import subprocess
import sys
import tkinter as tk
from tkinter import Image, messagebox, ttk
from tkinter import filedialog
import webbrowser
import winreg

version = "1.000"
drive_vars = []
divider = "__________________________________________________________________________________________________________________________________________________________________________________________________"

def is_admin():
    """
    Check for admin privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """
    Request the script to ask for administrator privileges.
    """
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, os.path.abspath(__file__), None, 1
        )
        sys.exit(0)  # Exit the original process if re-launch is successful
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Failed to elevate privileges: {e}")

def create_tooltip(widget, text):
    """
    Create a tooltip for a given widget.
    """
    tooltip = tk.Toplevel(widget)
    tooltip.withdraw()
    tooltip.wm_overrideredirect(True)
    tooltip.wm_geometry("+0+0")
    tooltip_label = tk.Label(
        tooltip,
        text=text,
        justify='left',
        background='yellow',
        relief='solid',
        borderwidth=1,
        wraplength=360
    )
    tooltip_label.pack()

    def enter(event):
        x = widget.winfo_rootx() + 20
        y = widget.winfo_rooty() + 20
        tooltip.wm_geometry(f"+{x}+{y}")
        tooltip.deiconify()

    def leave(event):
        tooltip.withdraw()

    widget.bind('<Enter>', enter)
    widget.bind('<Leave>', leave)

def set_regkey(hkey: winreg.HKEYType, subkey: string, newvalue: string, datatype: string, inverse: bool, silent: bool):
    global checkbox_variable
    try:
        key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE)
        if inverse:
            value = 0 if checkbox_variable.get() else 1
        else:
            value = 1 if checkbox_variable.get() else 0
        winreg.SetValueEx(key, newvalue, 0, datatype, value)
        winreg.CloseKey(key)
        if not silent:
            messagebox.showinfo("Porkspatch", "Registry value set successfully.")
    except Exception as e:
        if not silent:
            messagebox.showerror("Porkspatch", f"Error setting registry value: {e}")

def get_regkey(hkey: winreg.HKEYType, subkey: string):
    try:
        key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "PorkspatchBootAsSystem")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading LongPathsEnabled: {e}")
        return False
    
def create_regkey_checkbox(master, hkey: winreg.HKEYType, subkey: string, newvalue: string, datatype: string, inverse: bool, silent: bool, checkbox_title: string, tooltip: string):
    global regkey_var
    regkey_var = tk.IntVar(value=int(get_regkey(hkey, subkey)))
    regkey_checkbox = ttk.Checkbutton(master, text=checkbox_title, variable=regkey_var, command=set_regkey(hkey, subkey, newvalue, datatype, inverse, silent))
    regkey_checkbox.pack(padx=10, pady=1, anchor='w')
    create_tooltip(regkey_checkbox, tooltip)

def set_system_boot():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup", 0, winreg.KEY_SET_VALUE)
        value = 0 if boot_as_system_value.get() else 1
        winreg.SetValueEx(key, "CmdLine", 0, winreg.REG_SZ, "cmd.exe")
        winreg.SetValueEx(key, "SetupPhase", 0, winreg.REG_DWORD, value)
        winreg.SetValueEx(key, "SetupType", 0, winreg.REG_DWORD, value)
        winreg.SetValueEx(key, "SystemSetupInProgress", 0, winreg.REG_DWORD, value)
        winreg.SetValueEx(key, "PorkspatchBootAsSystem", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", "Registry values set successfully.")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting registry values: {e}")

def get_system_boot():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "PorkspatchBootAsSystem")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading LongPathsEnabled: {e}")
        return False

def set_long_paths_enabled():
    # Set or unset LongPathsEnabled registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem", 0, winreg.KEY_SET_VALUE)
        value = 1 if long_paths_var.get() else 0
        winreg.SetValueEx(key, "LongPathsEnabled", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Unlimited Max Paths set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Unlimited Max Paths: {e}")

def get_long_paths_enabled():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "LongPathsEnabled")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading LongPathsEnabled: {e}")
        return False

def set_verbose_login():
    # Set or unset VerboseLogon registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE)
        value = 1 if verbose_login.get() else 0
        winreg.SetValueEx(key, "VerboseStatus", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Verbose Logon set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Verbose Logon: {e}")

def get_verbose_login():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "VerboseStatus")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading VerboseStatus: {e}")
        return False

def set_low_disk_space_notifications():
    # Set or Unset NoLowDiskSpaceChecks registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE)
        value = 1 if low_disk_notif.get() else 0
        winreg.SetValueEx(key, "NoLowDiskSpaceChecks", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Low Disk Space Notifications set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Low Disk Space Notifications: {e}")

def get_low_disk_space_notifications():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "NoLowDiskSpaceChecks")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading NoLowDiskSpaceChecks: {e}")
        return False

def set_disable_defender():
    # Set or Unset DisableAntiSpyware registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", 0, winreg.KEY_SET_VALUE)
        value = 1 if disable_defender.get() else 0
        winreg.SetValueEx(key, "DisableAntiSpyware", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Disable Windows Defender set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Disable Windows Defender: {e}")

def get_disable_defender():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "DisableAntiSpyware")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading DisableAntiSpyware: {e}")
        return False

def set_disable_cmd():
    # Set or Unset DisableCMD registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE)
        value = 1 if disable_cmd_value.get() else 0
        winreg.SetValueEx(key, "DisableCMD", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Disable Command Prompt set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Disable Command Prompt: {e}")

def get_disable_cmd():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "DisableCMD")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading DisableCMD: {e}")
        return False

def set_disable_ipv6():
    # Set or Unset DisabledComponents registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", 0, winreg.KEY_SET_VALUE)
        value = 1 if disable_ipv6_value.get() else 0
        winreg.SetValueEx(key, "DisabledComponents", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Disable IPv6 set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Disable IPv6: {e}")

def get_disable_ipv6():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "DisabledComponents")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading DisabledComponents: {e}")
        return False
    
def set_enable_lgco():
    # Set or Unset DisabledComponents registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SafeBoot\Options", 0, winreg.KEY_SET_VALUE)
        value = 1 if enable_last_good_configuration_option_value.get() else 0
        winreg.SetValueEx(key, "UseLastKnownGood", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Enable Last Good Configuration set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Enable Last Good Configuration: {e}")

def get_enable_lgco():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SafeBoot\Options", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "UseLastKnownGood")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading UseLastKnownGood: {e}")
        return False
    
def set_disable_windows_store():
    # Set or Unset RemoveWindowsStore registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\WindowsStore", 0, winreg.KEY_SET_VALUE)
        value = 1 if disable_windows_store_value.get() else 0
        winreg.SetValueEx(key, "RemoveWindowsStore", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Remove Windows Store set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Remove Windows Store: {e}")

def get_disable_windows_store():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\WindowsStore", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "RemoveWindowsStore")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading RemoveWindowsStore: {e}")
        return False
    
def set_disable_auto_updates():
    # Set or Unset NoAutoUpdate registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", 0, winreg.KEY_SET_VALUE)
        value = 1 if disable_no_auto_update_value.get() else 0
        winreg.SetValueEx(key, "NoAutoUpdate", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Disable Windows Auto Update set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Disable Windows Auto Update: {e}")

def get_disable_auto_updates():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "NoAutoUpdate")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading NoAutoUpdate: {e}")
        return False

def open_twitter():
    webbrowser.open_new("https://twitter.com/PorkyLIVE_")

def get_hidden_drives():
    """
    Get the current NoDrives value from the registry and return a bitmask of hidden drives.
    """
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    try:
        # Open registry key for reading
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
        no_drives_value, _ = winreg.QueryValueEx(key, "NoDrives")
        winreg.CloseKey(key)
        return no_drives_value
    except FileNotFoundError:
        # If the key or value does not exist, assume no drives are hidden
        return 0
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return 0
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading NoDrives: {e}")
        return 0

def set_hidden_drives():
    """
    Create the registry key if it doesn't exist and set the NoDrives value.
    """
    try:
        # Path to the registry key
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        
        # Open or create the registry key
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        
        # Calculate the NoDrives value
        no_drives_value = 0
        for i, drive_var in enumerate(drive_vars):
            if drive_var.get() == 1:
                no_drives_value |= (1 << i)

        # Set the NoDrives value
        winreg.SetValueEx(key, "NoDrives", 0, winreg.REG_DWORD, no_drives_value)
        
        winreg.CloseKey(key)
        
        # Inform the user
        #messagebox.showinfo("Porkspatch", f"NoDrives set to {no_drives_value}. Please restart Explorer.")
        restartexplorernow = messagebox.askyesno("Porkspatch", f"NoDrives set to {no_drives_value}. Do you want to restart the Explorer now?")
        if restartexplorernow == True:
            restart_explorer()

    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting NoDrives: {e}")

def load_path_variable():
    """
    Load the PATH environment variable and display it in the Listbox.
    """
    global path_listbox
    path_listbox.delete(0, tk.END)  # Clear the listbox
    path = os.environ.get("PATH", "")
    if path:
        paths = path.split(os.pathsep)
        for p in paths:
            path_listbox.insert(tk.END, p)

def save_path_variable():
    """
    Save the updated PATH environment variable.
    """
    global path_listbox
    new_path_list = path_listbox.get(0, tk.END)
    new_path = os.pathsep.join(new_path_list).strip()
    try:
        # Save to environment variable
        os.environ["PATH"] = new_path

        # Optionally save to registry
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Session Manager\Environment", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)

        messagebox.showinfo("Porkspatch", "PATH variable updated successfully.")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error updating PATH variable: {e}")

def browse_path():
    global path_entry
    directory = filedialog.askdirectory()
    if directory:
        path_entry.delete(0, tk.END)
        path_entry.insert(0, directory)


def add_path():
    """
    Add a new path to the PATH environment variable.
    """
    global path_entry, path_listbox
    new_path = path_entry.get().strip()
    if new_path:
        if new_path not in path_listbox.get(0, tk.END):
            path_listbox.insert(tk.END, new_path)
            path_entry.delete(0, tk.END)  # Clear the entry box
        else:
            messagebox.showinfo("Porkspatch", "Path already exists.")
    else:
        messagebox.showinfo("Porkspatch", "Please enter a valid path.")

def remove_path():
    """
    Remove the selected path from the PATH environment variable.
    """
    global path_listbox
    try:
        selected_index = path_listbox.curselection()
        if selected_index:
            path_listbox.delete(selected_index)
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error removing path: {e}")

def open_selected_path():
    """
    Open the selected path in the PATH environment variable using Windows File Explorer.
    """
    global path_listbox
    try:
        selected_index = path_listbox.curselection()
        if selected_index:
            selected_path = path_listbox.get(selected_index)
            if os.path.exists(selected_path):
                subprocess.Popen(f'explorer "{selected_path}"')
            else:
                messagebox.showerror("Porkspatch", f"The path does not exist:\n{selected_path}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error opening path: {e}")

def restart_explorer():
    """
    Restart Windows Explorer.
    """
    try:
        os.system("taskkill /f /im explorer.exe")
        os.system("start explorer.exe")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error restarting Explorer: {e}")

def system_cmd():
    try:
        subprocess.run(f'runas /user:{os.environ.get("computername")}\\SYSTEM {os.environ.get("windir")}\system32\cmd.exe', shell=True)
    except Exception as e:
        messagebox.showerror("Porkspatch", e)

def initialize_checkboxes(no_drives_value):
    """
    Initialize the checkboxes based on the NoDrives value.
    """
    for i in range(26):
        if no_drives_value & (1 << i):
            drive_vars[i].set(1)

def add_context_menu():
    name = entry_name.get()
    command = entry_command.get()
    description = entry_desc.get()
    if not name or not command or not description:
        messagebox.showwarning("Input Error", "Name and Command are required.")
        return

    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{name}")
        winreg.SetValueEx(key, '', 0, winreg.REG_SZ, description)
        cmdkey = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{name}\\command")
        winreg.SetValueEx(cmdkey, '', 0, winreg.REG_SZ, command)
        messagebox.showinfo("Success", f"Added context menu item '{name}'.")
        update_context_menu_list()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to add context menu item: {e}")

def remove_context_menu():
    name = entry_name.get()
    if not name:
        messagebox.showwarning("Input Error", "Name is required.")
        return

    try:
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{name}\\command")
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{name}")
        messagebox.showinfo("Success", f"Removed context menu item '{name}'.")
        update_context_menu_list()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to remove context menu item: {e}")

def update_context_menu_list():
    listbox_context_menu.delete(0, tk.END)
    try:
        key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "*\shell")
        i = 0
        while True:
            name = winreg.EnumKey(key, i)
            try:
                cmdtest = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{name}\\command")
                if cmdtest:
                    listbox_context_menu.insert(tk.END, name)
            except Exception:
                pass
            i += 1
    except OSError:
        pass
    except Exception as e:
        messagebox.showerror("Porkspatch", e)

def load_context_menu_details(event):
    selected_item = listbox_context_menu.get(listbox_context_menu.curselection())
    try:
        desckey = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{selected_item}")
        description, _ = winreg.QueryValueEx(desckey, '')
        cmdkey = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{selected_item}\\command")
        command, _ = winreg.QueryValueEx(cmdkey, '')
        entry_name.delete(0, tk.END)
        entry_name.insert(0, selected_item)
        entry_desc.delete(0, tk.END)
        entry_desc.insert(0, description)
        entry_command.delete(0, tk.END)
        entry_command.insert(0, command)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load context menu details: {e}")

def browse_new_cmd():
    global browse_result_cmd
    command = filedialog.askopenfilename()
    if command:
        entry_command.delete(0, tk.END)
        entry_command.insert(0, command)





def main():
    try:
        ### INITIAL STARTUP ###
        init_setup_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(init_setup_key, "SystemSetupInProgress", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(init_setup_key)
        
        ### WINDOW CONFIGURATION ###
        window = tk.Tk()
        window.title("Porkspatch")
        window.geometry("768x480")
        window.configure(bg="pink")
        window.resizable(False, False)

        # Set window icon (if it exists)
        try:
            window.iconbitmap("porkspatch.ico")
        except Exception as e_icon:
            print(f"[ERR] {e_icon}")

        ### CONTEXT ###
        title_label = tk.Label(
            window,
            text="Welcome to Porkspatch!",
            font=("Comic Sans", 24),
            pady=20,
            background="pink"
        )
        title_label.pack(anchor="n")

        notebook = ttk.Notebook(window)
        notebook.pack(expand=True, fill="both")

        welcome_tab = ttk.Frame(notebook)
        global_tab = ttk.Frame(notebook)
        boot_tab = ttk.Frame(notebook)
        path_tab = ttk.Frame(notebook)
        drives_tab = ttk.Frame(notebook)
        context_menu_tab = ttk.Frame(notebook)
        about_tab = ttk.Frame(notebook)

        ## WELCOME TAB ##
        notebook.add(welcome_tab, text="Welcome")
        story_text = """
        Once upon a time in the land of Porkspatch, there lived a brave knight named Sir Bacon. 
        Sir Bacon was known far and wide for his courage and love for crispy adventures.

        One sunny morning, Sir Bacon received a message from the king, summoning him to the castle. 
        The king spoke of a mysterious dragon that had been terrorizing the kingdom, 
        and only Sir Bacon could save the day.

        With his trusty sword and shield in hand, Sir Bacon set off on his quest to find the dragon's lair...

        — ChatGPT
        """
        story_text_widget = tk.Label(welcome_tab, text=story_text, font=("Arial", 12, "italic"), pady=20, wraplength=600)
        story_text_widget.pack(expand=False, fill='x')

        if is_admin():
            admin_checker_text = "You have administrator privileges! :)"
        else:
            admin_checker_text = "No administrator privileges... :("

        admin_checker = tk.Label(welcome_tab, text=admin_checker_text, font=("Arial", 16))
        admin_checker.pack(expand=False,anchor='s')

        version_label = tk.Label(welcome_tab, text=f"Version: {version}", font=("Arial", 8), foreground='gray')
        version_label.pack(expand=False,anchor='s')
        create_tooltip(version_label, f"""Username: {os.environ.get("username")}
        User Directory: {os.environ.get("userprofile")}
        AppData: {os.environ.get("appdata")}
        LocalAppData: {os.environ.get("localappdata")}
        Temp: {os.environ.get("temp")}
        OneDrive: {os.environ.get("onedrive")}

Computer: {os.environ.get("computername")}
        Operating System: {os.environ.get("OS")}
        Windows Directory: {os.environ.get("windir")}
        System Drive: {os.environ.get("systemdrive")}
        System Root: {os.environ.get("systemroot")}

Processor: {os.environ.get("processor_identifier")}
        Architecture: {os.environ.get("processor_architecture")}
        Level: {os.environ.get("processor_level")}
        Revision: {os.environ.get("processor_revision")}
        Amount: {os.environ.get("number_of_processors")}

PATH Extensions: {os.environ.get("pathext")}""")

        ## GLOBAL SETTINGS TAB ##
        notebook.add(global_tab, text="Global Settings")

        file_system_frame = ttk.LabelFrame(global_tab, text="File System")
        file_system_frame.grid(row=1, column=1, sticky='n')

        security_frame = ttk.LabelFrame(global_tab, text="Security")
        security_frame.grid(row=1, column=2, sticky='n')

        login_frame = ttk.LabelFrame(global_tab, text="Login & Booting")
        login_frame.grid(row=1, column=3, sticky='n')

        networking_frame = ttk.LabelFrame(global_tab, text="Networking")
        networking_frame.grid(row=2, column=1, sticky='n')

        windows_frame = ttk.LabelFrame(global_tab, text="Windows")
        windows_frame.grid(row=2, column=2, sticky='n')

        global long_paths_var
        long_paths_var = tk.IntVar(value=int(get_long_paths_enabled()))
        long_paths_checkbox = ttk.Checkbutton(file_system_frame, text="Unlimited Max Paths", variable=long_paths_var, command=set_long_paths_enabled)
        long_paths_checkbox.pack(padx=10, pady=1, anchor='w')
        create_tooltip(long_paths_checkbox, "This will remove the 260 character limit for file paths.")

        global verbose_login
        verbose_login = tk.IntVar(value=int(get_verbose_login()))
        verbose_login_checkbox = ttk.Checkbutton(login_frame, text="Verbose Login", variable=verbose_login, command=set_verbose_login)
        verbose_login_checkbox.pack(padx=10, pady=1, anchor='w')
        create_tooltip(verbose_login_checkbox, "This will show additional information during logging in and out, starting up Windows, and shutting down, instead of the standard messages like 'Welcome!' and 'Shutting down...'.")

        global low_disk_notif
        low_disk_notif = tk.IntVar(value=int(get_low_disk_space_notifications()))
        low_disk_checkbox = ttk.Checkbutton(file_system_frame, text="Disable Low Disk Space Notifications", variable=low_disk_notif, command=set_low_disk_space_notifications)
        low_disk_checkbox.pack(padx=10, pady=1, anchor='w')
        create_tooltip(low_disk_checkbox, "This will disable the notifications regarding low storage space.")

        global disable_defender
        disable_defender_value = tk.IntVar(value=int(get_disable_defender()))
        disable_defender = ttk.Checkbutton(security_frame, text="Disable Windows Defender", variable=disable_defender_value, command=set_disable_defender)
        disable_defender.pack(padx=10, pady=1, anchor='w')
        create_tooltip(disable_defender, """This will disable Windows Defender. 
        > WARNING: This will put your computer at risk if no other AntiVirus is running!""")

        global disable_cmd_value
        disable_cmd_value = tk.IntVar(value=int(get_disable_cmd()))
        disable_cmd = ttk.Checkbutton(security_frame, text="Disable Command Prompt", variable=disable_cmd_value, command=set_disable_cmd)
        disable_cmd.pack(padx=10, pady=1, anchor='w')
        create_tooltip(disable_cmd, """This will disable the Command Prompt. You can still open the Command Prompt, but will no longer allow user input.
        > NOTE: You might need to restart your computer for this setting to take effect.""")

        global disable_ipv6_value
        disable_ipv6_value = tk.IntVar(value=int(get_disable_ipv6()))
        disable_ipv6 = ttk.Checkbutton(networking_frame, text="Disable IPv6 Protocol", variable=disable_ipv6_value, command=set_disable_ipv6)
        disable_ipv6.pack(padx=10, pady=1, anchor='w')
        create_tooltip(disable_ipv6, """This will disable the IPv6 Network Protocol.
        > NOTE: You might need to restart your computer for this setting to take effect.""")

        global enable_last_good_configuration_option_value
        enable_last_good_configuration_option_value = tk.IntVar(value=int(get_enable_lgco()))
        enable_last_good_configuration_option = ttk.Checkbutton(login_frame, text="Enable Last Good Configuration Option", variable=enable_last_good_configuration_option_value, command=set_enable_lgco)
        enable_last_good_configuration_option.pack(padx=10, pady=1, anchor='w')
        create_tooltip(enable_last_good_configuration_option, """This will enable the 'Last Known Good Configuration' option in the boot menu.""")

        global disable_windows_store_value
        disable_windows_store_value = tk.IntVar(value=int(get_disable_windows_store()))
        disable_windows_store = ttk.Checkbutton(windows_frame, text="Disable Windows Store", variable=disable_windows_store_value, command=set_disable_windows_store)
        disable_windows_store.pack(padx=10, pady=1, anchor='w')
        create_tooltip(disable_windows_store, """This will disable the Windows Store.""")

        global disable_no_auto_update_value
        disable_no_auto_update_value = tk.IntVar(value=int(get_disable_auto_updates()))
        disable_no_auto_update = ttk.Checkbutton(windows_frame, text="Disable Automatic Updates", variable=disable_no_auto_update_value, command=set_disable_auto_updates)
        disable_no_auto_update.pack(padx=10, pady=1, anchor='w')
        create_tooltip(disable_no_auto_update, """This will disable the automatic downloading and installing of Windows Updates.
        > WARNING: This obviously creates a security risk if Windows Updates are ignored altogether.""")

        ## BOOT SETTINGS TAB ##
        #notebook.add(boot_tab, text="Boot")
        
        global boot_as_system_value
        boot_as_system_value = tk.IntVar(value=int(get_system_boot()))
        boot_as_system_button = ttk.Checkbutton(boot_tab, text="Boot as SYSTEM", command=set_system_boot)
        boot_as_system_button.pack(pady=10)
        create_tooltip(boot_as_system_button, """This will configure Windows to start a command prompt with SYSTEM privileges on next boot.
        > WARNING: Porkspatch currently has no way to disable this setting once this setting is actively in use. Only use if you know how the Windows Registry Editor works, and how to disable the effects of this setting.
        > BUG: Porkspatch no longer opens when this setting is used.""")

        ## PATH EDITOR TAB ##
        notebook.add(path_tab, text="PATH Inspector")
        path_frame = ttk.Frame(path_tab)
        path_frame.pack(fill="both", expand=True, padx=20, pady=10)

        global path_listbox, path_entry
        path_listbox = tk.Listbox(path_frame, selectmode=tk.SINGLE, height=10)
        path_listbox.pack(fill="both", expand=True, pady=5)

        path_buttons_frame = ttk.Frame(path_frame)
        path_buttons_frame.pack(fill=tk.X, pady=5)

        path_save_button = ttk.Button(path_buttons_frame, text="Save PATH", command=save_path_variable)
        path_save_button.pack(side=tk.LEFT, padx=5)

        path_load_button = ttk.Button(path_buttons_frame, text="Load PATH", command=load_path_variable)
        path_load_button.pack(side=tk.LEFT, padx=5)

        path_remove_button = ttk.Button(path_buttons_frame, text="Remove Selected", command=remove_path)
        path_remove_button.pack(side=tk.LEFT, padx=5)

        path_open_button = ttk.Button(path_buttons_frame, text="Open Selected Path", command=open_selected_path)
        path_open_button.pack(side=tk.LEFT, padx=5)

        path_entry_frame = ttk.Frame(path_frame)
        path_entry_frame.pack(fill=tk.X, pady=5)

        path_entry = tk.Entry(path_entry_frame)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        path_browse = ttk.Button(path_entry_frame, text="Browse...", command=browse_path)
        path_browse.pack(side=tk.LEFT, padx=5)

        path_add_button = ttk.Button(path_entry_frame, text="Add Path", command=add_path)
        path_add_button.pack(side=tk.LEFT, padx=5)

        load_path_variable()

        ## CONTEXT MENU TAB ##
        notebook.add(context_menu_tab, text="Context Menu")

        # Name and Command labels and entries
        global reg
        
        global entry_name
        lbl_name = ttk.Label(context_menu_tab, text="Name:")
        lbl_name.grid(row=0, column=0, padx=10, pady=5, sticky='w')
        entry_name = ttk.Entry(context_menu_tab)
        entry_name.grid(row=0, column=1, padx=10, pady=5, sticky='ew')
        create_tooltip(entry_name, "The internalized name for this Context Menu item. This name will only show up in the list below.")

        global entry_desc
        lbl_desc = ttk.Label(context_menu_tab, text="Description:")
        lbl_desc.grid(row=1, column=0, padx=10, pady=5, sticky='w')
        entry_desc = ttk.Entry(context_menu_tab)
        entry_desc.grid(row=1, column=1, padx=10, pady=5, sticky='ew')
        create_tooltip(entry_desc, "The title of the Context Menu item that will show up inside the Context Menu.")

        global entry_command
        lbl_command = ttk.Label(context_menu_tab, text="Command:")
        lbl_command.grid(row=2, column=0, padx=10, pady=5, sticky='w')
        entry_command = ttk.Entry(context_menu_tab)
        entry_command.grid(row=2, column=1, padx=10, pady=5, sticky='ew')
        create_tooltip(entry_command, "The program or command to run. Enter the full path to the program, or use the 'Browse...' button.")

        global browse_command
        browse_command = ttk.Button(context_menu_tab, text="Browse...", command=browse_new_cmd)
        browse_command.grid(row=2, column=2, padx=10, pady=5, sticky='e')

        # Buttons for add and remove
        btn_add = ttk.Button(context_menu_tab, text="Add", command=add_context_menu)
        btn_add.grid(row=3, column=0, padx=10, pady=5, sticky='n')

        btn_remove = ttk.Button(context_menu_tab, text="Remove", command=remove_context_menu)
        btn_remove.grid(row=3, column=1, padx=10, pady=5, sticky='nw')

        # Listbox to show current context menu items
        global listbox_context_menu
        listbox_context_menu = tk.Listbox(context_menu_tab)
        listbox_context_menu.grid(row=4, column=0, columnspan=2, padx=10, pady=0, sticky='nsew')
        listbox_context_menu.bind('<<ListboxSelect>>', load_context_menu_details)

        # Make the listbox expand with window resize
        context_menu_tab.rowconfigure(4, weight=1)
        context_menu_tab.columnconfigure(1, weight=1)

        update_context_menu_list()

        ## DRIVES TAB ##
        notebook.add(drives_tab, text="Hide Drives")

        # Drive Checkboxes
        current_no_drives = get_hidden_drives()
        
        for index, drive in enumerate(string.ascii_uppercase):
            var = tk.IntVar()
            row, col = divmod(index, 12)
            chk = ttk.Checkbutton(drives_tab, text=f"{drive}:", variable=var)
            chk.grid(row=row, column=col, padx=5, pady=5)
            drive_vars.append(var)
            create_tooltip(chk, f"Hide drive {drive}: from the Windows Explorer. It will still show up in other programs.")

        initialize_checkboxes(current_no_drives)

        hide_drives_button = ttk.Button(drives_tab, text="Hide Selected Drives", command=set_hidden_drives)
        hide_drives_button.grid(row=3, column=3, columnspan=26, sticky='W')
        create_tooltip(hide_drives_button, "Apply drive hide settings. You will need to restart the Explorer to see the effects.")

        restart_explorer_button = ttk.Button(drives_tab, text="Restart Windows Explorer", command=restart_explorer)
        restart_explorer_button.grid(row=3, column=7, columnspan=454, sticky='W',)

        drive_divider = tk.Label(drives_tab, text=divider, foreground='light gray')
        drive_divider.grid(row=4, columnspan=26)

        ## ABOUT TAB ##
        notebook.add(about_tab, text="About")

        prog_credits = """
        Special thanks to:
            - PorkyLIVE
            - ChatGPT
        """
        prog_credits_widget = tk.Label(about_tab, text=prog_credits, font=("Arial", 12, "italic"), padx=20, pady=20)
        prog_credits_widget.pack(expand=True, fill='x')

        twitter_button = ttk.Button(about_tab, text="Twitter", command=open_twitter)
        twitter_button.pack(side=tk.BOTTOM, padx=20, pady=20)

        # Start the main event loop
        window.mainloop()

    except Exception as e:
        print(f"[ERR] {e}")

# Run the application
if __name__ == "__main__":
    if not is_admin():
        run_as_admin()
    else:
        main()
