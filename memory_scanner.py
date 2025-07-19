import psutil
import ctypes
from ctypes import wintypes
import struct

class MemoryScanner:
    def __init__(self, process_name):
        self.process = self.get_process_by_name(process_name)
        self.handle = None
        
    def get_process_by_name(self, name):
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == name:
                return proc
        return None
    
    def open_process(self):
        if not self.process:
            return False
        
        # Windows API constants
        PROCESS_ALL_ACCESS = 0x1F0FFF
        kernel32 = ctypes.windll.kernel32
        
        self.handle = kernel32.OpenProcess(
            PROCESS_ALL_ACCESS, 
            False, 
            self.process.pid
        )
        return self.handle != 0
    
    def read_memory(self, address, size):
        if not self.handle:
            return None
            
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t()
        
        success = ctypes.windll.kernel32.ReadProcessMemory(
            self.handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(bytes_read)
        )
        
        return buffer.raw if success else None
    
    def scan_for_value(self, value, data_type='int'):
        """Escaneia a memória procurando por um valor específico"""
        results = []
        
        # Obter informações de memória do processo
        for region in self.get_memory_regions():
            data = self.read_memory(region['base'], region['size'])
            if not data:
                continue
                
            # Procurar pelo valor na região
            if data_type == 'int':
                pattern = struct.pack('<i', value)
            elif data_type == 'float':
                pattern = struct.pack('<f', value)
            else:
                pattern = value.encode() if isinstance(value, str) else value
            
            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                results.append(region['base'] + pos)
                offset = pos + 1
                
        return results
    
    def get_memory_regions(self):
        """Obtém regiões de memória do processo"""
        regions = []
        # Implementação simplificada - na prática você usaria VirtualQueryEx
        # para obter informações detalhadas das regiões de memória
        return regions
    
    def close(self):
        if self.handle:
            ctypes.windll.kernel32.CloseHandle(self.handle)


if __name__ == "__main__":
    # Exemplo de uso
    scanner = MemoryScanner("notepad.exe")
    if scanner.open_process():
        addresses = scanner.scan_for_value(1337, 'int')
        print(f"Valor encontrado em: {addresses}")
        scanner.close()