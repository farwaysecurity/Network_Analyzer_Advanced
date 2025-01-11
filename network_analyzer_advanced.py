import tkinter as tk
from tkinter import ttk
import psutil
import socket
import threading
import time
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class AdvancedNetworkAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("Farway Advanced Network Analyzer 0.0.1")
      
        self.geometry("1000x800")
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Connections tab
        self.conn_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.conn_frame, text="Connections")
        
        # Create connections treeview
        self.tree = ttk.Treeview(self.conn_frame, columns=('Protocol', 'Local Address', 'Remote Address', 'Status'))
        self.tree.heading('#0', text='ID')
        self.tree.heading('Protocol', text='Protocol')
        self.tree.heading('Local Address', text='Local Address')
        self.tree.heading('Remote Address', text='Remote Address')
        self.tree.heading('Status', text='Status')
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Bandwidth tab
        self.bandwidth_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.bandwidth_frame, text="Bandwidth")
        
        # Create matplotlib figure for bandwidth graph
        self.figure = Figure(figsize=(8, 4))
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, self.bandwidth_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initialize data for bandwidth monitoring
        self.bandwidth_data = {'time': [], 'sent': [], 'recv': []}
        self.last_sent = 0
        self.last_recv = 0
        
        # Start monitoring thread
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor_network)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def update_bandwidth_graph(self):
        self.ax.clear()
        self.ax.plot(self.bandwidth_data['time'], self.bandwidth_data['sent'], label='Upload')
        self.ax.plot(self.bandwidth_data['time'], self.bandwidth_data['recv'], label='Download')
        self.ax.set_xlabel('Time (s)')
        self.ax.set_ylabel('Bandwidth (MB/s)')
        self.ax.legend()
        self.ax.grid(True)
        self.canvas.draw()
    
    def monitor_network(self):
        start_time = time.time()
        while self.running:
            # Update connections
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            connections = psutil.net_connections()
            for i, conn in enumerate(connections):
                try:
                    protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    status = conn.status
                    
                    self.tree.insert('', tk.END, text=str(i), 
                                   values=(protocol, laddr, raddr, status))
                except:
                    continue
            
            # Update bandwidth data
            net_stats = psutil.net_io_counters()
            current_time = time.time() - start_time
            
            # Calculate bandwidth in MB/s
            if self.last_sent > 0:
                sent_bandwidth = (net_stats.bytes_sent - self.last_sent) / 1048576
                recv_bandwidth = (net_stats.bytes_recv - self.last_recv) / 1048576
                
                self.bandwidth_data['time'].append(current_time)
                self.bandwidth_data['sent'].append(sent_bandwidth)
                self.bandwidth_data['recv'].append(recv_bandwidth)
                
                # Keep only last 30 seconds of data
                if len(self.bandwidth_data['time']) > 30:
                    self.bandwidth_data['time'].pop(0)
                    self.bandwidth_data['sent'].pop(0)
                    self.bandwidth_data['recv'].pop(0)
                
                self.update_bandwidth_graph()
            
            self.last_sent = net_stats.bytes_sent
            self.last_recv = net_stats.bytes_recv
            
            time.sleep(1)
    
    def on_closing(self):
        self.running = False
        self.destroy()

if __name__ == "__main__":
    app = AdvancedNetworkAnalyzer()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
