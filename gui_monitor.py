import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, get_if_list, get_if_addr, IP, TCP, UDP, ICMP
from collections import Counter
from threading import Thread
from queue import Queue
import socket
import requests

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Responsive Network Monitor (with Geolocation)")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        self.is_sniffing = False
        self.sniffer_thread = None
        self.resolver_thread = None
        
        # --- Thread-safe Queues for communication ---
        self.lookup_queue = Queue()
        self.results_queue = Queue()
        
        self.protocol_counter = Counter()
        self.src_ip_counter = Counter()
        self.country_counter = Counter()
        self.total_packets = 0
        
        self.hostname_cache = {}
        self.ip_country_cache = {}
        self.pending_resolution = set()

        self.setup_styles()
        self.setup_ui()
        self.update_gui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#e1e1e1')
        style.configure('TLabel', background='#e1e1e1', font=('Segoe UI', 10))
        style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'))
        style.configure('TButton', font=('Segoe UI', 10), padding=5)
        style.configure('Green.TButton', foreground='white', background='#28a745')
        style.configure('Red.TButton', foreground='white', background='#dc3545')
        style.configure('TNotebook', background='#e1e1e1')
        style.configure('TNotebook.Tab', font=('Segoe UI', 10, 'bold'), padding=[10, 5])
        style.configure('Treeview', font=('Segoe UI', 10), rowheight=25)
        style.configure('Treeview.Heading', font=('Segoe UI', 10, 'bold'))
        style.map('Treeview', background=[('selected', '#0078d7')], foreground=[('selected', 'white')])
        style.configure('TLabelframe', background='#e1e1e1', borderwidth=1, relief="groove")
        style.configure('TLabelframe.Label', background='#e1e1e1', font=('Segoe UI', 11, 'bold'))

    def setup_ui(self):
        main_paned_window = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        top_frame = ttk.Frame(main_paned_window, padding=10)
        main_paned_window.add(top_frame, weight=1)
        self._create_control_panel(top_frame)
        self._create_info_panel(top_frame)
        notebook_frame = ttk.Frame(main_paned_window)
        main_paned_window.add(notebook_frame, weight=5)
        self._create_notebook(notebook_frame)
        self.status_var = tk.StringVar(value="Ready. Select an interface and start sniffing.")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def get_active_interfaces(self):
        active_interfaces = []
        all_interfaces = get_if_list()
        for iface in all_interfaces:
            ip = get_if_addr(iface)
            if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                active_interfaces.append(iface)
        return active_interfaces if active_interfaces else all_interfaces

    def _create_control_panel(self, parent):
        control_frame = ttk.LabelFrame(parent, text="Controls")
        control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        ttk.Label(control_frame, text="Network Interface:").pack(padx=10, pady=(10, 0), anchor='w')
        self.interfaces = self.get_active_interfaces()
        self.iface_var = tk.StringVar(value=self.interfaces[0] if self.interfaces else "")
        self.iface_selector = ttk.Combobox(control_frame, textvariable=self.iface_var, values=self.interfaces, state='readonly')
        self.iface_selector.pack(padx=10, pady=5, fill=tk.X)
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(padx=10, pady=10, fill=tk.X)
        self.start_button = ttk.Button(button_frame, text="Start Sniffing", command=self.start_monitoring, style='Green.TButton')
        self.start_button.pack(side=tk.LEFT, expand=True, fill=tk.X)
        self.stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=self.stop_monitoring, state=tk.DISABLED, style='Red.TButton')
        self.stop_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5, 0))
        ttk.Button(control_frame, text="Clear Statistics", command=self.clear_stats).pack(padx=10, pady=(10, 0), fill=tk.X)

    def _create_info_panel(self, parent):
        info_frame = ttk.LabelFrame(parent, text="Live Statistics")
        info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.packet_count_var = tk.StringVar(value="Total Packets: 0")
        ttk.Label(info_frame, textvariable=self.packet_count_var, font=('Segoe UI', 12, 'bold')).pack(anchor='w', padx=10, pady=10)

    def _create_notebook(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True)
        # Protocol Tab
        protocol_frame = ttk.Frame(notebook, padding=5)
        notebook.add(protocol_frame, text="📊 Protocol Distribution")
        self.protocol_tree = ttk.Treeview(protocol_frame, columns=('protocol', 'count', 'percentage'), show='headings')
        self.protocol_tree.heading('protocol', text='Protocol'); self.protocol_tree.column('protocol', width=150, anchor=tk.W)
        self.protocol_tree.heading('count', text='Count'); self.protocol_tree.column('count', width=100, anchor=tk.CENTER)
        self.protocol_tree.heading('percentage', text='Percentage'); self.protocol_tree.column('percentage', width=120, anchor=tk.CENTER)
        self.protocol_tree.pack(fill=tk.BOTH, expand=True)
        # IP Traffic Tab
        ip_frame = ttk.Frame(notebook, padding=5)
        notebook.add(ip_frame, text="🌐 IP Traffic")
        self.ip_tree = ttk.Treeview(ip_frame, columns=('ip', 'count', 'hostname'), show='headings')
        self.ip_tree.heading('ip', text='Source IP Address'); self.ip_tree.column('ip', width=200, anchor=tk.W)
        self.ip_tree.heading('count', text='Packet Count'); self.ip_tree.column('count', width=120, anchor=tk.CENTER)
        self.ip_tree.heading('hostname', text='Hostname'); self.ip_tree.column('hostname', width=300, anchor=tk.W)
        self.ip_tree.pack(fill=tk.BOTH, expand=True)
        # Geolocation Tab
        geo_frame = ttk.Frame(notebook, padding=5)
        notebook.add(geo_frame, text="🌍 Geolocation")
        self.geo_tree = ttk.Treeview(geo_frame, columns=('country', 'count'), show='headings')
        self.geo_tree.heading('country', text='Country'); self.geo_tree.column('country', width=300, anchor=tk.W)
        self.geo_tree.heading('count', text='Packets'); self.geo_tree.column('count', width=120, anchor=tk.CENTER)
        self.geo_tree.pack(fill=tk.BOTH, expand=True)

    def start_monitoring(self):
        selected_iface = self.iface_var.get()
        if not selected_iface:
            messagebox.showerror("Error", "Please select a network interface.")
            return

        self.clear_stats()
        self.is_sniffing = True
        
        self.status_var.set(f"Sniffing on interface: {selected_iface}...")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.iface_selector.config(state=tk.DISABLED)
        
        self.sniffer_thread = Thread(target=self.sniffing_worker, args=(selected_iface,), daemon=True)
        self.resolver_thread = Thread(target=self.resolution_worker, daemon=True)
        
        self.sniffer_thread.start()
        self.resolver_thread.start()

    def stop_monitoring(self):
        self.status_var.set("Stopping...")
        self.is_sniffing = False
        self.stop_button.config(state=tk.DISABLED)

    def sniffing_worker(self, iface):
        try:
            sniff(prn=self.process_packet, iface=iface, store=False, stop_filter=lambda x: not self.is_sniffing)
        except Exception as e:
            self.root.after_idle(messagebox.showerror, "Sniffing Error", f"An error occurred: {e}\n\nTry running with administrator/root privileges.")
        finally:
            self.root.after_idle(self.on_sniffing_stop)

    def resolution_worker(self):
        while True:
            ip_to_resolve = self.lookup_queue.get()
            if ip_to_resolve is None:
                break # Sentinel to exit thread

            # Perform slow lookups here
            hostname = "N/A"
            try:
                hostname = socket.gethostbyaddr(ip_to_resolve)[0]
            except (socket.herror, socket.gaierror):
                pass

            country = "N/A"
            try:
                response = requests.get(f"http://ip-api.com/json/{ip_to_resolve}?fields=country", timeout=2)
                if response.status_code == 200:
                    country = response.json().get('country', 'N/A')
            except requests.RequestException:
                pass
            
            # Put the complete result onto the results queue
            self.results_queue.put({'ip': ip_to_resolve, 'hostname': hostname, 'country': country})

    def on_sniffing_stop(self):
        self.status_var.set("Sniffer stopped. Ready.")
        self.start_button.config(state=tk.NORMAL)
        self.iface_selector.config(state='readonly')

    def process_packet(self, packet):
        if not self.is_sniffing: return
        
        if IP in packet:
            src_ip = packet[IP].src
            self.total_packets += 1
            self.src_ip_counter[src_ip] += 1
            
            # If we've never seen this IP before, add it to the lookup queue
            if src_ip not in self.hostname_cache and src_ip not in self.pending_resolution:
                if not src_ip.startswith(("192.168.", "10.", "127.")):
                    self.pending_resolution.add(src_ip)
                    self.lookup_queue.put(src_ip)

            if TCP in packet: proto = "TCP"
            elif UDP in packet: proto = "UDP"
            elif ICMP in packet: proto = "ICMP"
            else: proto = "Other IP"
            self.protocol_counter[proto] += 1

    def update_gui(self):
        # Process results from the resolver thread
        while not self.results_queue.empty():
            result = self.results_queue.get_nowait()
            ip = result['ip']
            self.hostname_cache[ip] = result['hostname']
            self.ip_country_cache[ip] = result['country']
            if ip in self.pending_resolution:
                self.pending_resolution.remove(ip)

        self.packet_count_var.set(f"Total Packets: {self.total_packets}")
        
        # Update Protocol Tree
        self.protocol_tree.delete(*self.protocol_tree.get_children())
        for proto, count in self.protocol_counter.most_common():
            percentage = (count / self.total_packets * 100) if self.total_packets > 0 else 0
            self.protocol_tree.insert('', tk.END, values=(proto, count, f"{percentage:.1f}%"))
        
        # Update IP Tree
        self.ip_tree.delete(*self.ip_tree.get_children())
        for ip, count in self.src_ip_counter.most_common(50):
            hostname = self.hostname_cache.get(ip, "Resolving...")
            self.ip_tree.insert('', tk.END, values=(ip, count, hostname))
        
        # Update Geolocation Tree
        self.country_counter.clear()
        for ip, count in self.src_ip_counter.items():
            country = self.ip_country_cache.get(ip)
            if country and country != "N/A":
                self.country_counter[country] += count

        self.geo_tree.delete(*self.geo_tree.get_children())
        for country, count in self.country_counter.most_common(50):
            self.geo_tree.insert('', tk.END, values=(country, count))

        self.root.after(1000, self.update_gui)

    def clear_stats(self):
        self.protocol_counter.clear()
        self.src_ip_counter.clear()
        self.country_counter.clear()
        self.hostname_cache.clear()
        self.ip_country_cache.clear()
        self.pending_resolution.clear()
        self.total_packets = 0
        # Clear any pending items in queues
        while not self.lookup_queue.empty(): self.lookup_queue.get_nowait()
        while not self.results_queue.empty(): self.results_queue.get_nowait()
        self.status_var.set("Statistics cleared.")

    def on_close(self):
        self.is_sniffing = False # Signal sniffing thread to stop
        self.lookup_queue.put(None) # Signal resolver thread to stop
        
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=0.5)
        if self.resolver_thread and self.resolver_thread.is_alive():
            self.resolver_thread.join(timeout=0.5)
            
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.mainloop()