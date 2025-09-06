#!/usr/bin/env python3

# A professional serial/TCP communication GUI application.
# The code is structured using an object-oriented approach to ensure
# each tab's functionality and widgets are encapsulated and independent.

import tkinter as tk
from tkinter import ttk, font
import serial
import threading
import time
from serial.tools import list_ports
import winsound
import json
import os
import socket
import subprocess
import platform
from ping3 import ping
from queue import Queue
from gui_util import safe_tk_call

# You can customize these fonts
STATUS_FONT = ("Helvetica", 10, "bold")
RTT_FONT = ("Helvetica", 10)

# --- Global Constants ---
# A list of standard baud rates
BAUD_RATES = [9600, 19200, 38400, 57600, 115200, 256000, 500000]

# List of predefined commands for the dropdown
PRESET_COMMANDS = ["", "/lcd ", "/ping ", "/lan ", "/ttl ", "/rs-422 ", "/usb ", "/conf ", "/reset"]

# List of End-of-Line options
EOL_OPTIONS = ["\\r\\n", "\\n", "\\r", "None"]

# Configuration key-value pairs for the /conf command
CONFIG_OPTIONS = {
    "ttl": "1",
    "rs-422": "1",
    "usb": "1",
    "lan": "1",
    "alcd": "1",
    "server-ip": "192.168.1.200",
    "server-port": "8585",
    "rs-422-baudrate": "115200",
    "rs-422-frame": "8n1",
    "ttl-baudrate": "115200",
    "ttl-frame": "8n1",
    "alcd-rows": "2",
    "alcd-columns": "16"
}

# --- Helper Functions (can be used by multiple classes) ---

def create_circle(canvas, x, y, r, color):
    """Draws a circle on a canvas."""
    x0 = x - r
    y0 = y - r
    x1 = x + r
    y1 = y + r
    return canvas.create_oval(x0, y0, x1, y1, fill=color, outline=color)

def update_status_lights(light_canvases, status):
    """Updates the status lights based on the connection status."""
    disconnected_canvas, connecting_canvas, connected_canvas = light_canvases
    
    colors = {
        "disconnected": ("red", "gray", "gray"),
        "connecting": ("gray", "yellow", "gray"),
        "connected": ("gray", "gray", "#32CD32")
    }
    
    disconnected_canvas.itemconfig(1, fill=colors[status][0])
    connecting_canvas.itemconfig(1, fill=colors[status][1])
    connected_canvas.itemconfig(1, fill=colors[status][2])

class ConfigurationManager:
    """A class to manage saving and loading application settings."""
    def __init__(self, filename="config.json"):
        self.filename = filename
        self.config = {}
        self.load_config()

    def load_config(self):
        """Loads configuration from a JSON file."""
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    self.config = json.load(f)
            except (IOError, json.JSONDecodeError) as e:
                print(f"Error loading config file: {e}")
                self.config = {}
        else:
            self.config = {}

    def save_config(self, port, baud_rate):
        """Saves the current port and baud rate to the config file."""
        self.config['port'] = port
        self.config['baud_rate'] = baud_rate
        try:
            with open(self.filename, 'w') as f:
                json.dump(self.config, f, indent=4)
        except IOError as e:
            print(f"Error saving config file: {e}")

class SerialManager:
    """Manages all serial communication and its corresponding GUI elements."""
    def __init__(self, tab_frame, status_text_widget, eol_widgets):
        self.tab_frame = tab_frame
        self.status_text = status_text_widget
        self.eol_widgets = eol_widgets
        self.ser = None
        self.config_manager = ConfigurationManager()
        self.create_serial_widgets()
        
    def create_serial_widgets(self):
        """Creates all GUI widgets for the Serial tab."""
        # Serial input frame
        input_frame = tk.Frame(self.tab_frame, bg="#F0F0F0")
        input_frame.pack(side=tk.TOP, fill=tk.X, pady=5)

        default_font = font.nametofont("TkDefaultFont")
        default_font.config(size=10)

        ttk.Label(input_frame, text="Port :", font=default_font).grid(row=0, column=0, padx=5, pady=5)
        self.ports_combobox = ttk.Combobox(input_frame, values=self.scan_ports(), state="readonly", width=11, font=default_font)
        self.ports_combobox.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Baud Rate :", font=default_font).grid(row=0, column=2, padx=5, pady=5)
        self.baud_combobox = ttk.Combobox(input_frame, values=BAUD_RATES, state="readonly", width=6, font=default_font)
        self.baud_combobox.grid(row=0, column=3, padx=5, pady=5)
        self.baud_combobox.set(115200)

        input_frame.columnconfigure(4, weight=1)
        self.connect_button = ttk.Button(input_frame, text="Connect", command=self.toggle_connection_threaded)
        self.connect_button.grid(row=0, column=4, padx=5, pady=5, sticky="ew")
                
        refresh_button = ttk.Button(input_frame, text="Refresh", command=self.update_port_list)
        refresh_button.grid(row=1, column=0, columnspan=4, padx=5, pady=2, sticky="ew")
        
        # Status lights frame
        lights_frame = tk.Frame(input_frame, bg="#F0F0F0")
        lights_frame.grid(row=1, column=4, padx=5, pady=0, sticky=tk.E)
        
        self.disconnected_canvas = tk.Canvas(lights_frame, width=25, height=25)
        self.disconnected_canvas.pack(side=tk.LEFT, padx=1, pady=0)
        create_circle(self.disconnected_canvas, 12, 12, 10, "red")
        
        self.connecting_canvas = tk.Canvas(lights_frame, width=25, height=25)
        self.connecting_canvas.pack(side=tk.LEFT, padx=1, pady=0)
        create_circle(self.connecting_canvas, 12, 12, 10, "gray")
        
        self.connected_canvas = tk.Canvas(lights_frame, width=25, height=25)
        self.connected_canvas.pack(side=tk.LEFT, padx=1, pady=0)
        create_circle(self.connected_canvas, 12, 12, 10, "gray")
        
        self.update_ui(connected=False)
        self.load_last_config()

    def load_last_config(self):
        """Loads the last used port and baud rate from the config file."""
        if self.config_manager.config:
            last_port = self.config_manager.config.get('port')
            last_baud = self.config_manager.config.get('baud_rate')

            available_ports = self.scan_ports()
            if last_port in available_ports:
                self.ports_combobox.set(last_port)
            
            if last_baud in BAUD_RATES:
                self.baud_combobox.set(last_baud)

    def scan_ports(self):
        """Scans and returns a list of available serial ports."""
        ports = list_ports.comports()
        return [port.device for port in ports]

    def update_port_list(self):
        """Updates the list of available ports in the combobox."""
        new_ports = self.scan_ports()
        self.ports_combobox['values'] = new_ports
        current_port = self.ports_combobox.get()
        if current_port not in new_ports:
            self.ports_combobox.set("Select a port")
        self.status_text.insert(tk.END, "Ports list updated.\n")
        self.status_text.see(tk.END)

    def toggle_connection_threaded(self):
        """Starts the connection/disconnection process in a separate thread."""
        if not (self.ser and self.ser.is_open):
            update_status_lights((self.disconnected_canvas, self.connecting_canvas, self.connected_canvas), "connecting")
            self.status_text.insert(tk.END, "Connecting...\n")
        conn_thread = threading.Thread(target=self._toggle_connection_logic, daemon=True)
        conn_thread.start()

    def _toggle_connection_logic(self):
        """Handles the actual connection/disconnection logic in a separate thread."""
        if self.ser and self.ser.is_open:
            self.ser.close()
            self.tab_frame.after(0, lambda: self.update_ui(connected=False))
        else:
            try:
                port_name = self.ports_combobox.get()
                baud_rate = int(self.baud_combobox.get())
                if not port_name or "Select" in port_name:
                    self.tab_frame.after(0, lambda: self.status_text.insert(tk.END, "Error : No valid port selected.\n", 'error'))
                    self.tab_frame.after(0, lambda: update_status_lights((self.disconnected_canvas, self.connecting_canvas, self.connected_canvas), "disconnected"))
                    return
                self.ser = serial.Serial(port_name, baud_rate, timeout=0.01)
                self.config_manager.save_config(port_name, baud_rate)

                read_thread = threading.Thread(target=self.read_from_port, daemon=True)
                read_thread.start()
                self.tab_frame.after(0, lambda: self.update_ui(connected=True, port_name=port_name, baud_rate=baud_rate))
            except ValueError :
                self.tab_frame.after(0, lambda: self.status_text.insert(tk.END, "Error : Invalid baud rate. Please select a number.\n", 'error'))
                self.tab_frame.after(0, lambda: update_status_lights((self.disconnected_canvas, self.connecting_canvas, self.connected_canvas), "disconnected"))
            except serial.SerialException as e:
                self.tab_frame.after(0, lambda: self.status_text.insert(tk.END, f"Error : Could not open the port {port_name}. {e}\n", 'error'))
                self.tab_frame.after(0, lambda: self.update_ui(connected=False))

    def update_ui(self, connected, port_name=None, baud_rate=None, unexpected_disconnect=False):
        """Updates the UI elements after a connection attempt."""
        if connected:
            update_status_lights((self.disconnected_canvas, self.connecting_canvas, self.connected_canvas), "connected")
            self.status_text.delete(1.0, tk.END)
            self.status_text.insert(tk.END, f"Successfully connected to {port_name} at {baud_rate} baud.\n", 'connected')
            self.connect_button.config(text="Disconnect")
            self.ports_combobox.config(state="disabled")
            self.baud_combobox.config(state="disabled")
        else:
            update_status_lights((self.disconnected_canvas, self.connecting_canvas, self.connected_canvas), "disconnected")
            if self.ser:
                self.ser = None
            self.status_text.insert(tk.END, "Disconnected from port.\n", 'disconnected')
            if unexpected_disconnect:
                self.status_text.insert(tk.END, "Connection lost unexpectedly. The port list has been refreshed.\n", 'error')
                self.update_port_list()
            self.connect_button.config(text="Connect")
            self.ports_combobox.config(state="readonly")
            self.baud_combobox.config(state="readonly")
        self.status_text.see(tk.END)

    def read_from_port(self):
        """Reads data from the serial port in a separate thread."""
        while self.ser and self.ser.is_open:
            try:
                line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                if line:
                    winsound.Beep(615, 95) # Plays a sound when a message is received.
                    line_cleaned = line.replace('\x1a', '')
                    self.status_text.insert(tk.END, f"Received : {line_cleaned}\n\n", 'received')
                    self.status_text.see(tk.END)
            except serial.SerialException:
                if self.ser and self.ser.is_open:
                    self.ser.close()
                self.tab_frame.after(0, lambda: self.update_ui(connected=False, unexpected_disconnect=True))
                break

    def send_data(self, base_message):
        """Sends data through the serial port."""
        eol_option = self.eol_widgets[0].get()
        display_eol_var = self.eol_widgets[1]
        
        if self.ser and self.ser.is_open:
            if eol_option == "\\r\\n":
                final_message = base_message + '\r\n'
            elif eol_option == "\\n":
                final_message = base_message + '\n'
            elif eol_option == "\\r":
                final_message = base_message + '\r'
            else:
                final_message = base_message
            
            self.ser.write(final_message.encode('utf-8'))
            if display_eol_var.get():
                display_message = final_message.replace('\r', '\\r').replace('\n', '\\n')
            else:
                display_message = base_message
            self.status_text.insert(tk.END, f"Sent : {display_message}\n", 'sent')
            self.status_text.see(tk.END)
            
            if base_message.strip() == "/reset":
                self.status_text.insert(tk.END, "Reset command sent. Disconnecting from port.\n Please reconnect after the device has rebooted.\n", 'warning')
                self.status_text.see(tk.END)
                self.ser.close()
                self.update_ui(connected=False)
        else:
            self.status_text.insert(tk.END, "Error : Not connected to a serial port.\n", 'error')
            self.status_text.see(tk.END)

class TcpClientManager:
    """Manages all TCP communication and its corresponding GUI elements."""
    def __init__(self, tab_frame, status_text_widget, eol_widgets):
        self.tab_frame = tab_frame
        self.status_text = status_text_widget
        self.eol_widgets = eol_widgets
        self.sock = None
        self.read_thread = None
        self.is_connected = False
        self.create_tcp_widgets()

    def create_tcp_widgets(self):
        """Creates all GUI widgets for the TCP tab."""
        # TCP input frame
        input_frame = tk.Frame(self.tab_frame, bg="#F0F0F0")
        input_frame.pack(side=tk.TOP, fill=tk.X, pady=5)
        
        default_font = font.nametofont("TkDefaultFont")
        default_font.config(size=10) # Change 16 to your desired font size

        ttk.Label(input_frame, text="IP Address:", font=default_font).grid(row=0, column=0, padx=5, pady=5)
        self.ip_entry = ttk.Entry(input_frame, width=15, font=default_font)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        self.ip_entry.insert(0, "192.168.1.200")
        
        ttk.Label(input_frame, text="Port:", font=default_font).grid(row=0, column=2, padx=5, pady=5)
        self.port_entry = ttk.Entry(input_frame, width=8, font=default_font)
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)
        self.port_entry.insert(0, "8585")
        
        input_frame.columnconfigure(4, weight=1)
        self.connect_button = ttk.Button(input_frame, text="Connect", command=self.toggle_connection_threaded)
        self.connect_button.grid(row=0, column=4, padx=5, pady=5, sticky='ew')
        
        # Add a ping button and a status label in the next row
        self.ping_button = ttk.Button(input_frame, text="Ping", command=self.send_ping)
        self.ping_button.grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)

        self.ping_status_label = ttk.Label(input_frame, text="RTT : IDLE", font=default_font)
        self.ping_status_label.grid(row=1, column=1, padx=5, pady=2, sticky=tk.W)

         # Ping result label to show the RTT value
        self.ping_result_label = ttk.Label(input_frame, text="RTT : N/A", font=default_font)
        self.ping_result_label.grid(row=1, column=2, padx=5, pady=2, sticky=tk.W)

        # Status lights frame 
        lights_frame = tk.Frame(input_frame, bg="#F0F0F0")
        lights_frame.grid(row=1, column=4, padx=5, pady=0, sticky=tk.E)
        
        self.disconnected_canvas = tk.Canvas(lights_frame, width=25, height=25)
        self.disconnected_canvas.pack(side=tk.LEFT, padx=1, pady=0)
        create_circle(self.disconnected_canvas, 12, 12, 10, "red")
        
        self.connecting_canvas = tk.Canvas(lights_frame, width=25, height=25)
        self.connecting_canvas.pack(side=tk.LEFT, padx=1, pady=0)
        create_circle(self.connecting_canvas, 12, 12, 10, "gray")
        
        self.connected_canvas = tk.Canvas(lights_frame, width=25, height=25)
        self.connected_canvas.pack(side=tk.LEFT, padx=1, pady=0)
        create_circle(self.connected_canvas, 12, 12, 10, "gray")
        
        self.update_ui(connected=False)


    def send_ping(self):
        """
        Initiates an ICMP ping operation on a separate thread to avoid freezing the GUI.
        """
        self.ping_button.config(state=tk.DISABLED)
        self.ping_queue = Queue()
        ping_thread = threading.Thread(target=self._run_ping_logic)
        ping_thread.daemon = True
        ping_thread.start()
        self._check_ping_queue()

    def _run_ping_logic(self):
        """
        Executes ICMP ping logic in a separate thread.
        """
        try:
            target_ip = self.ip_entry.get().strip()
            if not target_ip:
                self.ping_queue.put(("Status: No IP Provided", "RTT: N/A"))
                return

            self.ping_queue.put(("Status: Pinging...", "RTT: N/A"))
            start_time = time.time()
            rtt = ping(target_ip, timeout=3, unit="ms")
            end_time = time.time()
            if rtt is None:
                self.ping_queue.put(("Status: Timeout", "RTT: N/A"))
            else:
                measured_rtt = (end_time - start_time) * 1000
                self.ping_queue.put(("Status: Success", f"RTT: {rtt:.2f} ms"))

        except PermissionError :
            self.ping_queue.put(("Status: Admin Required", "RTT: N/A"))
        except Exception as e:
            self.ping_queue.put((f"Status: Error - {e}", "RTT: N/A"))
        finally:
            self.ping_queue.put("ENABLE_BUTTON")

    def _check_ping_queue(self):
        """
        Periodically checks the queue for updates from the ping thread.
        """
        try:
            while not self.ping_queue.empty():
                item = self.ping_queue.get_nowait()
                if item == "ENABLE_BUTTON":
                    self.ping_button.config(state=tk.NORMAL)
                else:
                    status_text, rtt_text = item
                    self._update_ping_gui(status_text, rtt_text)
        except Exception as e:
            print("Queue Error :", e)
        finally:
            self.tab_frame.after(100, self._check_ping_queue)

    def _update_ping_gui(self, status_text, rtt_text):
        """
        Safely updates GUI elements from a different thread.
        """
        self.ping_status_label.config(text=status_text, font=STATUS_FONT, width= 15)
        self.ping_result_label.config(text=rtt_text, font=RTT_FONT, width=8)



    def toggle_connection_threaded(self):
        """Starts the TCP connection/disconnection process in a separate thread."""
        if not self.is_connected:
            update_status_lights((self.disconnected_canvas, self.connecting_canvas, self.connected_canvas), "connecting")
            self.status_text.insert(tk.END, "Connecting...\n")
        conn_thread = threading.Thread(target=self._toggle_connection_logic, daemon=True)
        conn_thread.start()

    def _toggle_connection_logic(self):
        """Handles the actual TCP connection/disconnection logic."""
        if self.is_connected:
            self.disconnect()
        else:
            host = self.ip_entry.get()
            port = self.port_entry.get()
            self.connect(host, port)

    def connect(self, host, port):
        """Attempts to establish a TCP connection."""
        if not host or not port:
            self.status_text.insert(tk.END, "Error : IP address and port are required.\n", 'error')
            self.status_text.see(tk.END)
            return False
        
        try:
            self.port = int(port)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(3)
            self.sock.connect((host, self.port))
            self.sock.settimeout(None)
            self.is_connected = True
            self.status_text.insert(tk.END, f"Successfully connected to TCP server at {host} : {self.port}\n", 'connected')
            self.status_text.see(tk.END)
            self.read_thread = threading.Thread(target=self.read_from_socket, daemon=True)
            self.read_thread.start()
            self.tab_frame.after(0, lambda: self.update_ui(connected=True))
            return True
        except (socket.error, ValueError) as e:
            self.status_text.insert(tk.END, f"Error : Could not connect to TCP server. {e}\n", 'error')
            self.status_text.see(tk.END)
            self.is_connected = False
            self.tab_frame.after(0, lambda: self.update_ui(connected=False))
            return False

    def disconnect(self):
        """Closes the TCP connection safely."""
        self.is_connected = False
        try:
            if self.sock:
                self.sock.close()
        except Exception as e:
            print(f"Error closing socket: {e}")
        self.sock = None

        # Schedule the UI update on the main thread
        self.tab_frame.after(0, lambda: self.update_ui(connected=False))
        
        # Check if the text widget still exists before inserting text.
        if self.status_text and self.status_text.winfo_exists():
            self.status_text.insert(tk.END, "Disconnected from TCP server.\n", 'disconnected')
            self.status_text.see(tk.END)    

    def read_from_socket(self):
        """Reads data from the TCP socket in a separate thread."""
        while self.is_connected:
            try:
                data = self.sock.recv(1024)
                if not data:
                    self.tab_frame.after(0, lambda: self.status_text.insert(tk.END, "Server closed the connection gracefully.\n", 'error'))
                    self.disconnect()
                    break
                decoded_data = data.decode('utf-8')
                self.tab_frame.after(0, lambda: self.status_text.insert(tk.END, f"Received TCP: {decoded_data}\n", 'received'))
                self.tab_frame.after(0, lambda: self.status_text.see(tk.END))
                winsound.Beep(915, 95)
            except socket.error as e:
                if self.is_connected:
                    self.tab_frame.after(0, lambda: self.status_text.insert(tk.END, f"TCP connection Error : {e}\n", 'error'))
                    self.tab_frame.after(0, lambda: self.status_text.see(tk.END))
                self.disconnect()
                break

    def send_data(self, base_message):
        """Sends data through the TCP socket."""
        eol_option = self.eol_widgets[0].get()
        display_eol_var = self.eol_widgets[1]
        
        if self.is_connected:
            if eol_option == "\\r\\n":
                final_message = base_message + '\r\n'
            elif eol_option == "\\n":
                final_message = base_message + '\n'
            elif eol_option == "\\r":
                final_message = base_message + '\r'
            else:
                final_message = base_message
            
            try:
                self.sock.sendall(final_message.encode('utf-8'))
                if display_eol_var.get():
                    display_message = final_message.replace('\r', '\\r').replace('\n', '\\n')
                else:
                    display_message = base_message
                self.status_text.insert(tk.END, f"Sent TCP: {display_message}\n", 'sent')
            except socket.error as e:
                self.status_text.insert(tk.END, f"Error sending data: {e}\n", 'error')
                # A socket error during send also means the connection is lost.
                self.disconnect()
            self.status_text.see(tk.END)
        else:
            self.status_text.insert(tk.END, "Error : TCP client is not connected.\n", 'error')
            self.status_text.see(tk.END)
        
    def update_ui(self, connected):
        """Updates the UI elements after a connection attempt for the given protocol."""
        if connected:
            update_status_lights((self.disconnected_canvas, self.connecting_canvas, self.connected_canvas), "connected")
            self.connect_button.config(text="Disconnect")
            self.ip_entry.config(state="disabled")
            self.port_entry.config(state="disabled")
        else:
            update_status_lights((self.disconnected_canvas, self.connecting_canvas, self.connected_canvas), "disconnected")
            self.connect_button.config(text="Connect")
            self.ip_entry.config(state="normal")
            self.port_entry.config(state="normal")
        self.status_text.see(tk.END)

class TcpServerManager:
    def __init__(self, tab_frame, status_text_widget, eol_widgets):
        self.tab_frame = tab_frame
        self.status_text = status_text_widget
        self.eol_widgets = eol_widgets
        self.server_socket = None
        self.client_threads = []
        self.is_running = False
        self.port_entry = None
        self.start_button = None
        self.client_sockets = []
        self.create_server_widgets()

    def create_server_widgets(self):
        input_frame = tk.Frame(self.tab_frame, bg="#F0F0F0")
        input_frame.pack(side=tk.TOP, fill=tk.X, pady=5)

        ttk.Label(input_frame, text="Port :", font="TkDefaultFont 10").grid(row=0, column=0, padx=5, pady=5)
        self.port_entry = ttk.Entry(input_frame, width=8, font="TkDefaultFont 10")
        self.port_entry.grid(row=0, column=1, padx=5, pady=5)
        self.port_entry.insert(0, "8585")

        self.start_button = ttk.Button(input_frame, text="Listen", command=self.toggle_server_threaded)
        self.start_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        input_frame.columnconfigure(2, weight=1)

    def toggle_server_threaded(self):
        thread = threading.Thread(target=self.toggle_server, daemon=True)
        thread.start()

    def toggle_server(self):
        if self.is_running:
            self.stop_server()
        else:
            self.start_server()

    def start_server(self):
        try:
            port = int(self.port_entry.get())
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)

            self.server_socket.bind(('', port))
            self.server_socket.listen(5)
            self.is_running = True
            self._log(f"TCP Server started on port {port}", 'connected')
            threading.Thread(target=self.accept_clients, daemon=True).start()
            self.start_button.config(text="Stop Server")
            self.port_entry.config(state="disabled")
        except Exception as e:
            self._log(f"Error starting server: {e}", 'error')

    def stop_server(self):
        self.is_running = False
        try:
            for client_sock in self.client_sockets:
                try:
                    client_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                client_sock.close()
            self.client_sockets.clear()

            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
                self.port_entry.config(state="enabled")

            self._log("TCP Server stopped", 'disconnected')
        except Exception as e:
            self._log(f"Error stopping server: {e}", 'error')
        self.start_button.config(text="Listen")
        self.port_entry.config(state="enabled")

    def accept_clients(self):
        while self.is_running and self.server_socket:
            try:
                client_socket, addr = self.server_socket.accept()
                client_socket.settimeout(1.0) 
                self.client_sockets.append(client_socket)
                self._log(f"Client connected from {addr}", 'connected')
                thread = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                thread.start()
                self.client_threads.append(thread)
            except OSError as e:
                if not self.is_running:
                    break
                self._log(f"Error accepting client: {e}", 'error')

    def handle_client(self, client_socket, addr):
        try:
            while self.is_running:
                if client_socket.fileno() == -1:
                    break
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    self._log(f"Received from {addr}: {data.decode()}", 'info')
                    winsound.Beep(1415, 95)
                    client_socket.sendall(data)
                except socket.timeout:
                    continue
                # except (ConnectionResetError, OSError) as e:
                #     self._log(f"Connection error with {addr}: {e}", 'error')
                #     break
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
            if client_socket in self.client_sockets:
                self.client_sockets.remove(client_socket)
            self._log(f"Client {addr} disconnected", 'disconnected')

    def send_data(self, base_message):
        if not self.is_running:
            self.status_text.insert(tk.END, "Error : Server is not running.\n", 'error')
            self.status_text.see(tk.END)
            return

        eol_option = self.eol_widgets[0].get()
        display_eol_var = self.eol_widgets[1]

        if not self.client_sockets:
            self.status_text.insert(tk.END, "Error : No TCP clients are connected.\n", 'error')
            self.status_text.see(tk.END)
            return

        if eol_option == "\\r\\n":
            final_message = base_message + '\r\n'
        elif eol_option == "\\n":
            final_message = base_message + '\n'
        elif eol_option == "\\r":
            final_message = base_message + '\r'
        else:
            final_message = base_message

        for client_sock in list(self.client_sockets):
            if client_sock.fileno() == -1:
                self.client_sockets.remove(client_sock)
                continue
            try:
                client_sock.sendall(final_message.encode('utf-8'))
                display_message = (
                    final_message.replace('\r', '\\r').replace('\n', '\\n')
                    if display_eol_var.get() else base_message
                )
                try:
                    peer = client_sock.getpeername()
                except OSError :
                    peer = 'Unknown'
                self.status_text.insert(tk.END, f"Sent to {peer}: {display_message}\n", 'sent')
            except (socket.error, OSError) as e:
                try:
                    peer = client_sock.getpeername()
                except OSError :
                    peer = 'Unknown'
                self.status_text.insert(tk.END, f"Error sending to {peer}: {e}\n", 'error')
                try:
                    client_sock.close()
                except Exception:
                    pass
                if client_sock in self.client_sockets:
                    self.client_sockets.remove(client_sock)
            self.status_text.see(tk.END)

    def _log(self, message, tag='info'):
        self.status_text.tag_configure('connected', foreground='green')
        self.status_text.tag_configure('disconnected', foreground='red')
        self.status_text.tag_configure('error', foreground='Maroon')
        self.status_text.tag_configure('info', foreground='black')
        self.status_text.insert(tk.END, f"{message}\n", tag)
        self.status_text.see(tk.END)

class UdpManager:
    """Manages all UDP communication and its corresponding GUI elements."""
    def __init__(self, tab_frame, status_text_widget, eol_widgets):
        self.tab_frame = tab_frame
        self.status_text = status_text_widget
        self.eol_widgets = eol_widgets
        self.sock = None
        self.is_connected = False
        self.read_thread = None
        self.create_udp_widgets()

    def create_udp_widgets(self):
        """Creates all GUI widgets for the UDP tab."""
        input_frame = tk.Frame(self.tab_frame, bg="#F0F0F0")
        input_frame.pack(side=tk.TOP, fill=tk.X, pady=5)
        
        default_font = font.nametofont("TkDefaultFont")
        default_font.config(size=10)

        ttk.Label(input_frame, text="Local Port :", font=default_font).grid(row=0, column=0, padx=5, pady=5)
        self.local_port_entry = ttk.Entry(input_frame, width=8, font=default_font)
        self.local_port_entry.grid(row=0, column=1, padx=5, pady=5)
        self.local_port_entry.insert(0, "9000")

        ttk.Label(input_frame, text="Dest. IP :", font=default_font).grid(row=1, column=0, padx=5, pady=5)
        self.dest_ip_entry = ttk.Entry(input_frame, width=15, font=default_font)
        self.dest_ip_entry.grid(row=1, column=1, padx=5, pady=5)
        self.dest_ip_entry.insert(0, "192.168.1.200")

        ttk.Label(input_frame, text="Dest. Port:", font=default_font).grid(row=1, column=2, padx=5, pady=5)
        self.dest_port_entry = ttk.Entry(input_frame, width=8, font=default_font)
        self.dest_port_entry.grid(row=1, column=3, padx=5, pady=5)
        self.dest_port_entry.insert(0, "9001")

        input_frame.columnconfigure(2, weight=1)
        input_frame.columnconfigure(3, weight=1)
        input_frame.columnconfigure(4, weight=1)
        self.connect_button = ttk.Button(input_frame, text="Listen", command=self.toggle_connection_threaded)
        self.connect_button.grid(row=0, column=2, columnspan=3, padx=5, pady=5, sticky='ew')

        # Status lights frame 
        lights_frame = tk.Frame(input_frame, bg="#F0F0F0")
        lights_frame.grid(row=1, column=4, padx=5, pady=0, sticky=tk.E)
        
        self.disconnected_canvas = tk.Canvas(lights_frame, width=25, height=25)
        self.disconnected_canvas.pack(side=tk.LEFT, padx=1, pady=0)
        create_circle(self.disconnected_canvas, 12, 12, 10, "red")
        
        self.connecting_canvas = tk.Canvas(lights_frame, width=25, height=25)
        self.connecting_canvas.pack(side=tk.LEFT, padx=1, pady=0)
        create_circle(self.connecting_canvas, 12, 12, 10, "gray")
        
        self.connected_canvas = tk.Canvas(lights_frame, width=25, height=25)
        self.connected_canvas.pack(side=tk.LEFT, padx=1, pady=0)
        create_circle(self.connected_canvas, 12, 12, 10, "gray")
        
        self.update_ui(connected=False)

    def toggle_connection_threaded(self):
        thread = threading.Thread(target=self._toggle_connection_logic, daemon=True)
        thread.start()

    def _toggle_connection_logic(self):
        if self.is_connected:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        """Binds the UDP socket to a local port."""
        local_port = self.local_port_entry.get()
        if not local_port:
            self.status_text.insert(tk.END, "Error : A local port is required to listen.\n", 'error')
            self.status_text.see(tk.END)
            return
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('', int(local_port)))
            self.is_connected = True
            self.status_text.insert(tk.END, f"Listening on UDP port {local_port}\n", 'connected')
            self.status_text.see(tk.END)
            self.read_thread = threading.Thread(target=self.read_from_socket, daemon=True)
            self.read_thread.start()
            self.tab_frame.after(0, lambda: self.update_ui(connected=True))
        except (socket.error, ValueError) as e:
            self.status_text.insert(tk.END, f"Error : Could not bind to port. {e}\n", 'error')
            self.status_text.see(tk.END)
            self.is_connected = False
            self.tab_frame.after(0, lambda: self.update_ui(connected=False))

    def disconnect(self):
        """Closes the UDP socket safely."""
        self.is_connected = False
        if self.sock:
            self.sock.close()
        self.sock = None
        self.status_text.insert(tk.END, "UDP socket closed.\n", 'disconnected')
        self.status_text.see(tk.END)
        self.tab_frame.after(0, lambda: self.update_ui(connected=False))

    def read_from_socket(self):
        """Reads data from the UDP socket in a separate thread."""
        while self.is_connected and self.sock:
            try:
                data, addr = self.sock.recvfrom(1024)
                decoded_data = data.decode('utf-8', errors='ignore')
                self.tab_frame.after(0, lambda: self.status_text.insert(tk.END, f"Received from {addr}: {decoded_data}\n", 'received'))
                self.tab_frame.after(0, lambda: self.status_text.see(tk.END))
                winsound.Beep(1115, 95)
            except socket.error as e:
                if self.is_connected:
                    self.tab_frame.after(0, lambda: self.status_text.insert(tk.END, f"UDP socket Error : {e}\n", 'error'))
                self.disconnect()
                break

    def send_data(self, base_message):
        """Sends data through the UDP socket."""
        dest_ip = self.dest_ip_entry.get()
        dest_port = self.dest_port_entry.get()
        
        if not self.is_connected:
            self.status_text.insert(tk.END, "Error : UDP socket is not listening.\n", 'error')
            self.status_text.see(tk.END)
            return
        
        if not dest_ip or not dest_port:
            self.status_text.insert(tk.END, "Error : Destination IP and Port are required for sending.\n", 'error')
            self.status_text.see(tk.END)
            return

        eol_option = self.eol_widgets[0].get()
        display_eol_var = self.eol_widgets[1]

        if eol_option == "\\r\\n":
            final_message = base_message + '\r\n'
        elif eol_option == "\\n":
            final_message = base_message + '\n'
        elif eol_option == "\\r":
            final_message = base_message + '\r'
        else:
            final_message = base_message
        
        try:
            self.sock.sendto(final_message.encode('utf-8'), (dest_ip, int(dest_port)))
            if display_eol_var.get():
                display_message = final_message.replace('\r', '\\r').replace('\n', '\\n')
            else:
                display_message = base_message
            self.status_text.insert(tk.END, f"Sent to {dest_ip}:{dest_port}: {display_message}\n", 'sent')
        except (socket.error, ValueError) as e:
            self.status_text.insert(tk.END, f"Error sending data: {e}\n", 'error')
        self.status_text.see(tk.END)

    def update_ui(self, connected):
        """Updates the UI elements after a connection attempt for the given protocol."""
        if connected:
            update_status_lights((self.disconnected_canvas, self.connecting_canvas, self.connected_canvas), "connected")
            self.connect_button.config(text="Stop")
            self.local_port_entry.config(state="disabled")
        else:
            update_status_lights((self.disconnected_canvas, self.connecting_canvas, self.connected_canvas), "disconnected")
            self.connect_button.config(text="Listen")
            self.local_port_entry.config(state="normal")
        self.status_text.see(tk.END)

class App:
    """The main application class that sets up the GUI and manages tabs."""
    def __init__(self, window):
        self.window = window
        self.window.title("Tahamtan Serial/TCP Comm | Dev by Afshin Moradzadeh")
        self.window.geometry("515x615")
        self.window.configure(bg="#F0F0F0")
        # window.resizable(False, False)
        self.style = ttk.Style()
        self.style.configure("TCombobox", font="TkDefaultFont 10")
        self.style.configure("TButton", font="TkDefaultFont 10")
        self.style.configure("TNotebook.Tab", font=("TkDefaultFont", 11))

        # Initialize tab variables to None to prevent errors before setup
        self.serial_tab = None
        self.tcp_client_tab = None
        self.tcp_server_tab = None
        self.udp_tab = None
        self.tab_control = None
      
        self.setup_gui()
        
    def setup_gui(self):
        """Sets up the main GUI components including the notebook and tabs."""
        main_frame = tk.Frame(self.window, bg="#F0F0F0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=3, pady=5)
              
        self.tab_control = ttk.Notebook(main_frame)
        self.tab_control.pack(fill=tk.BOTH, expand=True)
        
        # --- Create tabs and their content ---
        self.serial_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.serial_tab, text="Serial")

        self.tcp_client_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tcp_client_tab, text="TCP Client")

        self.tcp_server_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tcp_server_tab, text="TCP Server")

        self.udp_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.udp_tab, text="UDP")
        
        # Create a single Text widget with a scrollbar for each tab
        # This will be passed to the respective Manager class
        # Serial Status/Output Text Box
        serial_text_with_scroll_frame = tk.Frame(self.serial_tab)
        serial_text_with_scroll_frame.pack(side=tk.BOTTOM, padx=(10, 10), pady=2, fill=tk.BOTH, expand=True)
        serial_scrollbar = tk.Scrollbar(serial_text_with_scroll_frame)
        serial_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.serial_status_text = tk.Text(
            serial_text_with_scroll_frame, height=20, width=30, font="TkDefaultFont 11",
            yscrollcommand=serial_scrollbar.set, padx=5, wrap=tk.WORD, takefocus=False
        )
        self.serial_status_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.serial_status_text.bind("<Key>", lambda e: "break")
        self.serial_status_text.bind("<Button-1>", lambda e: "break")
        serial_scrollbar.config(command=self.serial_status_text.yview)

        # TCP Client Status/Output Text Box
        tcp_client_text_with_scroll_frame = tk.Frame(self.tcp_client_tab)
        tcp_client_text_with_scroll_frame.pack(side=tk.BOTTOM, padx=(10, 1), pady=5, fill=tk.BOTH, expand=True)
        tcp_client_scrollbar = tk.Scrollbar(tcp_client_text_with_scroll_frame)
        tcp_client_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tcp_client_status_text = tk.Text(
            tcp_client_text_with_scroll_frame, height=20, width=30, font="TkDefaultFont 11", 
            yscrollcommand=tcp_client_scrollbar.set, padx=5, wrap=tk.WORD, takefocus=False, bg="#FFF9F9"
        )
        self.tcp_client_status_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tcp_client_status_text.bind("<Key>", lambda e: "break")
        self.tcp_client_status_text.bind("<Button-1>", lambda e: "break")
        tcp_client_scrollbar.config(command=self.tcp_client_status_text.yview)

        # TCP Server Status/Output Text Box
        tcp_server_text_frame = tk.Frame(self.tcp_server_tab)
        tcp_server_text_frame.pack(side=tk.BOTTOM, padx=(10, 10), pady=2, fill=tk.BOTH, expand=True)
        tcp_server_scrollbar = tk.Scrollbar(tcp_server_text_frame)
        tcp_server_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tcp_server_status_text = tk.Text(
            tcp_server_text_frame, height=20, width=30, font="TkDefaultFont 11",
            yscrollcommand=tcp_server_scrollbar.set, padx=5, wrap=tk.WORD, takefocus=False, bg="#F8F8FA"
        )
        self.tcp_server_status_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tcp_server_status_text.bind("<Key>", lambda e: "break")
        self.tcp_server_status_text.bind("<Button-1>", lambda e: "break")
        tcp_server_scrollbar.config(command=self.tcp_server_status_text.yview)

        # UDP Status/Output Text Box
        udp_text_frame = tk.Frame(self.udp_tab)
        udp_text_frame.pack(side=tk.BOTTOM, padx=(10, 10), pady=2, fill=tk.BOTH, expand=True)
        udp_scrollbar = tk.Scrollbar(tcp_server_text_frame)
        udp_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.udp_status_text = tk.Text(
            udp_text_frame, height=20, width=30, font="TkDefaultFont 11",
            yscrollcommand=udp_scrollbar.set, padx=5, wrap=tk.WORD, takefocus=False, bg="#E7F2E7"
        )
        self.udp_status_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.udp_status_text.bind("<Key>", lambda e: "break")
        self.udp_status_text.bind("<Button-1>", lambda e: "break")
        udp_scrollbar.config(command=self.udp_status_text.yview)

        # Configure the 'sent', 'received' etc. tags
        self.serial_status_text.tag_configure('sent', foreground='blue')
        self.serial_status_text.tag_configure('received', foreground='green')
        self.serial_status_text.tag_configure('error', foreground='red')
        self.serial_status_text.tag_configure('warning', foreground='orange')

        self.tcp_client_status_text.tag_configure('sent', foreground='blue')
        self.tcp_client_status_text.tag_configure('received', foreground='green')
        self.tcp_client_status_text.tag_configure('error', foreground='red')
        self.tcp_client_status_text.tag_configure('warning', foreground='orange')

        self.tcp_server_status_text.tag_configure('sent', foreground='blue')
        self.tcp_server_status_text.tag_configure('received', foreground='green')
        self.tcp_server_status_text.tag_configure('error', foreground='red')
        self.tcp_server_status_text.tag_configure('warning', foreground='orange')

        self.udp_status_text.tag_configure('sent', foreground='blue')
        self.udp_status_text.tag_configure('received', foreground='green')
        self.udp_status_text.tag_configure('error', foreground='red')
        self.udp_status_text.tag_configure('warning', foreground='orange')

        # --- Create the shared Send Frame at the bottom ---
        send_frame = tk.Frame(main_frame, bg="#F0F0F0")
        send_frame.pack(fill=tk.X, pady=5)
        send_frame.columnconfigure(1, weight=1)

        # 1. Preset combobox
        self.preset_combobox = ttk.Combobox(send_frame, values=PRESET_COMMANDS, width=7, font="TkDefaultFont 12")
        self.preset_combobox.grid(row=0, column=0, padx=5, pady=5)
        self.preset_combobox.set("")
        self.preset_combobox.bind("<<ComboboxSelected>>", self.handle_preset_selection)

        # 2. Custom message entry
        self.message_entry = ttk.Entry(send_frame, width=36, font="TkDefaultFont 12")
        self.message_entry.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")

        # 3. EOL combobox
        eol_label = ttk.Label(send_frame, text="EOL :", font="TkDefaultFont 9")
        eol_label.grid(row=0, column=2, padx=5, pady=5, sticky="e")
        self.eol_combobox = ttk.Combobox(send_frame, values=EOL_OPTIONS, state="readonly", width=5, font="TkDefaultFont 12")
        self.eol_combobox.grid(row=0, column=3, padx=5, pady=5)
        
        # Bind the <<NotebookTabChanged>> event to a handler function
        self.tab_control.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        
        # Initially set the correct value for the active tab (Serial)

        # 4. Checkbutton for EOL display with text
        self.display_eol_var = tk.BooleanVar(value=False)
        self.display_eol_checkbutton = ttk.Checkbutton(send_frame, text="Show \\r\\n", variable=self.display_eol_var)
        self.display_eol_checkbutton.grid(row=1, column=3, columnspan=2, padx=5, pady=5)

        # 5. Send button
        send_button = ttk.Button(send_frame, text="Send", command=self.send_data)
        send_button.grid(row=1, column=1, columnspan=1, pady=(5,5), sticky="ew")

        # 6. Dynamic config widgets (initially hidden)
        self.conf_key_combobox = None
        self.conf_value_entry = None
        
        # --- Instantiate the managers after the Text widgets are created ---
        self.serial_manager = SerialManager(self.serial_tab, self.serial_status_text, (self.eol_combobox, self.display_eol_var))
        self.tcp_client_manager = TcpClientManager(self.tcp_client_tab, self.tcp_client_status_text, (self.eol_combobox, self.display_eol_var))
        self.tcp_server_manager = TcpServerManager(self.tcp_server_tab, self.tcp_server_status_text, (self.eol_combobox, self.display_eol_var))
        self.udp_manager = UdpManager(self.udp_tab, self.udp_status_text, (self.eol_combobox, self.display_eol_var)) 

        # Bind the Ctrl+L keyboard shortcut to the clear function
        self.window.bind('<Control-l>', self.clear_status_box)
        self.window.bind('<Control-L>', self.clear_status_box)
        
        print("The config file is being saved to this path:")
        print(os.getcwd())

    def on_tab_changed(self, event):
        """
        Handles the tab change event to set the correct EOL value.
        """
        current_tab_text = self.tab_control.tab(self.tab_control.select(), "text")

        if current_tab_text == "Serial":
            self.eol_combobox.set("\\r\\n")
        else:
            self.eol_combobox.set("")

    def clear_status_box(self, event = None):
        """Clears all content from the status_box widget of the current tab."""
        current_tab = self.tab_control.tab(self.tab_control.select(), "text")
        if current_tab == "Serial":
            text_widget = self.serial_status_text
        elif current_tab == "TCP Client":
            text_widget = self.tcp_client_status_text
        elif current_tab == "TCP Server":
            text_widget = self.tcp_server_status_text
        elif current_tab == "UDP":
            text_widget = self.udp_status_text
        else:
            return
        text_widget.delete('1.0', 'end')

    def send_data(self):
        """Sends data from the input widgets based on the current active tab."""
        current_tab_text = self.tab_control.tab(self.tab_control.select(), "text")
        
        # Determine which text widget to use based on the current tab
        if current_tab_text == "Serial":
            text_widget = self.serial_status_text
            manager = self.serial_manager
        elif current_tab_text == "TCP Client":
            text_widget = self.tcp_client_status_text
            manager = self.tcp_client_manager
        elif current_tab_text == "TCP Server":
            text_widget = self.tcp_server_status_text
            manager = self.tcp_server_manager
        elif current_tab_text == "UDP":
            text_widget = self.udp_status_text
            manager = self.udp_manager
        else:
            return

        preset_command = self.preset_combobox.get()
        base_message = ""

        if preset_command == "/conf ":
            selected_key = self.conf_key_combobox.get()
            custom_value = self.conf_value_entry.get()
            if not selected_key:
                text_widget.insert(tk.END, "Error : Please select a configuration key.\n", 'error')
                text_widget.see(tk.END)
                return
            base_message = f"{preset_command}{selected_key} {custom_value}"
        else:
            custom_message = self.message_entry.get()
            base_message = f"{preset_command}{custom_message}"
        
        if not base_message.strip():
            text_widget.insert(tk.END, "Error : Please enter or select a command to send.\n", 'error')
            text_widget.see(tk.END)
            return
            
        manager.send_data(base_message)

    def handle_preset_selection(self, event):
        """Dynamically changes the message entry widget based on the selected command."""
        selected_command = self.preset_combobox.get()

        self.message_entry.grid_forget()
        if self.conf_key_combobox is not None:
            self.conf_key_combobox.grid_forget()
            self.conf_key_combobox.destroy()
            self.conf_key_combobox = None
        if self.conf_value_entry is not None:
            self.conf_value_entry.grid_forget()
            self.conf_value_entry.destroy()
            self.conf_value_entry = None

        self.conf_key_var = tk.StringVar()
        self.conf_value_var = tk.StringVar()

        if selected_command == "/conf ":
            if CONFIG_OPTIONS:
                self.conf_key_combobox = ttk.Combobox(
                    self.message_entry.master,
                    textvariable=self.conf_key_var,
                    values=list(CONFIG_OPTIONS.keys()),
                    state="readonly",
                    font="TkDefaultFont 12"
                )
                self.conf_key_combobox.grid(row=0, column=1, padx=2, pady=5, sticky="ew")
                self.conf_key_combobox.bind("<<ComboboxSelected>>", self.update_conf_value)

                self.conf_value_entry = ttk.Entry(
                    self.message_entry.master,
                    textvariable=self.conf_value_var,
                    width=19,
                    font="TkDefaultFont 12"
                )
                self.conf_value_entry.grid(row=1, column=2, padx=2, pady=5)
        elif selected_command == "/reset":
            self.message_entry.delete(0, tk.END)
            self.message_entry.grid(row=0, column=1, padx=5, pady=5)
            self.message_entry.config(state="disabled")
        else:
            self.message_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
            self.message_entry.config(state="normal")

    def update_conf_value(self, event):
        """Updates the value entry with the default value for the selected key."""
        selected_key = self.conf_key_var.get().strip()
        if CONFIG_OPTIONS and selected_key in CONFIG_OPTIONS:
            self.conf_value_var.set(CONFIG_OPTIONS[selected_key])

if __name__ == "__main__":
    window = tk.Tk()
    app = App(window)
    window.mainloop()
    
    # This part will run after the window is closed
    try:
        if hasattr(app, "serial_manager") and app.serial_manager.ser and app.serial_manager.ser.is_open:
            app.serial_manager.ser.close()
    except Exception as e:
        print(f"Serial close Error : {e}")

    try:
        if app.tcp_client_manager.is_connected:
            app.tcp_client_manager.disconnect()
    except Exception as e:
        print(f"TCP client disconnect Error : {e}")

    try:
        if app.tcp_server_manager.is_running:
            app.tcp_server_manager.stop_server()
    except Exception as e:
        print(f"TCP server stop Error : {e}")

    try:
        if app.udp_manager.is_connected:
            app.udp_manager.disconnect()
    except Exception as e:
        print(f"UDP disconnect Error : {e}")