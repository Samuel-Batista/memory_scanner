import psutil
import ctypes
from ctypes import wintypes
import struct
import time
import pickle
import os

class MemoryScanner:
    def __init__(self, process_name):
        self.process = self.get_process_by_name(process_name)
        self.handle = None
        self.memory_snapshot = {}  # Armazena snapshot da memória
        
    def get_process_by_name(self, name):
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == name:
                return proc
        return None
        
    def open_process(self):
        if not self.process:
            return False
        
        # Windows API constants - máximas permissões
        PROCESS_ALL_ACCESS = 0x1F0FFF
        kernel32 = ctypes.windll.kernel32
        
        self.handle = kernel32.OpenProcess(
            PROCESS_ALL_ACCESS, 
            False, 
            self.process.pid
        )
        return self.handle != 0
        
    def read_memory(self, address, size):
        if not self.handle or address is None:
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
        
        return buffer.raw[:bytes_read.value] if success else None
    
    def full_memory_scan(self, data_types=['int'], save_to_file=True):
        """
        Faz um scan TOTAL da memória sem valor inicial específico.
        Cria um snapshot completo de todos os valores encontrados.
        
        Args:
            data_types: Lista de tipos de dados para extrair ['int', 'float', 'short', 'byte', 'double']
            save_to_file: Se deve salvar o snapshot em arquivo
            
        Returns:
            dict: Dicionário com todos os valores encontrados organizados por tipo
        """
        print("=== SCAN TOTAL DA MEMÓRIA (SEM VALOR INICIAL) ===")
        print("⚠️  Este processo pode demorar MUITO tempo e usar muita RAM!")
        print("⚠️  Recomendado para processos pequenos ou para criar snapshots iniciais")
        
        confirm = input("\nContinuar com scan total? (s/n): ").strip().lower()
        if confirm != 's':
            return {}
        
        # Obter todas as regiões de memória
        regions = self.get_all_memory_regions()
        total_size = sum(region['size'] for region in regions)
        
        print(f"\nIniciando scan total:")
        print(f"Regiões: {len(regions)}")
        print(f"Tamanho total: {total_size / (1024*1024):.2f} MB")
        print(f"Tipos de dados: {', '.join(data_types)}")
        
        # Estrutura para armazenar todos os valores
        all_values = {dtype: {} for dtype in data_types}  # {tipo: {endereço: valor}}
        
        scanned_size = 0
        start_time = time.time()
        
        for i, region in enumerate(regions):
            try:
                base_addr = region['base']
                size = region['size']
                
                if base_addr is None or size is None or size <= 0:
                    continue
                
                # Mostrar progresso
                progress = (i + 1) / len(regions) * 100
                elapsed = time.time() - start_time
                eta = (elapsed / (i + 1)) * (len(regions) - i - 1) if i > 0 else 0
                
                print(f"[{progress:5.1f}%] Região {i+1}/{len(regions)} | "
                      f"0x{base_addr:08X} ({size:,} bytes) | "
                      f"ETA: {eta/60:.1f}min")
                
                # Ler a região inteira
                data = self.read_memory(base_addr, size)
                if not data:
                    continue
                
                scanned_size += len(data)
                
                # Extrair valores de cada tipo de dado
                for data_type in data_types:
                    values_found = self._extract_values_from_data(data, base_addr, data_type)
                    all_values[data_type].update(values_found)
                
                # Mostrar estatísticas da região
                region_total = sum(len(all_values[dt]) for dt in data_types)
                print(f"  ✓ {region_total:,} valores extraídos desta região")
                
            except Exception as e:
                print(f"  ✗ Erro na região 0x{base_addr:08X}: {e}")
                continue
        
        elapsed_time = time.time() - start_time
        
        # Estatísticas finais
        print(f"\n=== SCAN TOTAL CONCLUÍDO ===")
        print(f"Tempo total: {elapsed_time/60:.2f} minutos")
        print(f"Memória escaneada: {scanned_size / (1024*1024):.2f} MB")
        
        total_values = 0
        for data_type in data_types:
            count = len(all_values[data_type])
            total_values += count
            print(f"{data_type.upper()}: {count:,} valores únicos")
        
        print(f"TOTAL: {total_values:,} valores extraídos")
        
        # Salvar snapshot
        if save_to_file and total_values > 0:
            self._save_snapshot(all_values)
        
        # Armazenar na classe para uso posterior
        self.memory_snapshot = all_values
        
        return all_values
    
    def _extract_values_from_data(self, data, base_addr, data_type):
        """Extrai todos os valores de um tipo específico dos dados binários"""
        values = {}
        
        try:
            if data_type == 'int':
                size = 4
                format_char = '<i'
            elif data_type == 'float':
                size = 4
                format_char = '<f'
            elif data_type == 'double':
                size = 8
                format_char = '<d'
            elif data_type == 'short':
                size = 2
                format_char = '<h'
            elif data_type == 'byte':
                size = 1
                format_char = '<B'
            else:
                return values
            
            # Extrair valores em intervalos do tamanho do tipo
            for offset in range(0, len(data) - size + 1, size):
                try:
                    value = struct.unpack(format_char, data[offset:offset + size])[0]
                    address = base_addr + offset
                    values[address] = value
                except:
                    continue
                    
        except Exception as e:
            print(f"Erro ao extrair {data_type}: {e}")
        
        return values
    
    def _save_snapshot(self, snapshot_data):
        """Salva o snapshot da memória em arquivo"""
        try:
            filename = f"memory_snapshot_{self.process.info['name']}_{self.process.pid}_{int(time.time())}.pkl"
            
            print(f"\nSalvando snapshot em: {filename}")
            with open(filename, 'wb') as f:
                pickle.dump({
                    'process_name': self.process.info['name'],
                    'process_pid': self.process.pid,
                    'timestamp': time.time(),
                    'data': snapshot_data
                }, f)
            
            file_size = os.path.getsize(filename) / (1024*1024)
            print(f"Snapshot salvo! Tamanho: {file_size:.2f} MB")
            
        except Exception as e:
            print(f"Erro ao salvar snapshot: {e}")
    
    def load_snapshot(self, filename):
        """Carrega um snapshot salvo anteriormente"""
        try:
            print(f"Carregando snapshot: {filename}")
            with open(filename, 'rb') as f:
                snapshot = pickle.load(f)
            
            self.memory_snapshot = snapshot['data']
            
            print(f"Snapshot carregado:")
            print(f"  Processo: {snapshot['process_name']} (PID: {snapshot['process_pid']})")
            print(f"  Data: {time.ctime(snapshot['timestamp'])}")
            
            total_values = sum(len(self.memory_snapshot[dt]) for dt in self.memory_snapshot)
            print(f"  Total de valores: {total_values:,}")
            
            return True
            
        except Exception as e:
            print(f"Erro ao carregar snapshot: {e}")
            return False
    
    def filter_snapshot_by_value(self, target_value, data_type='int', tolerance=0):
        """
        Filtra o snapshot procurando por um valor específico
        
        Args:
            target_value: Valor a procurar
            data_type: Tipo de dado
            tolerance: Tolerância para valores float/double
        """
        if not self.memory_snapshot or data_type not in self.memory_snapshot:
            print("Nenhum snapshot carregado ou tipo de dado não encontrado")
            return []
        
        print(f"Filtrando snapshot procurando por {target_value} ({data_type})")
        
        matches = []
        values_dict = self.memory_snapshot[data_type]
        
        for address, value in values_dict.items():
            if data_type in ['float', 'double']:
                if abs(value - target_value) <= tolerance:
                    matches.append((address, value))
            else:
                if value == target_value:
                    matches.append((address, value))
        
        print(f"Encontrados {len(matches)} matches no snapshot")
        return matches
    
    def filter_snapshot_by_range(self, min_value, max_value, data_type='int'):
        """Filtra o snapshot procurando valores em um range"""
        if not self.memory_snapshot or data_type not in self.memory_snapshot:
            print("Nenhum snapshot carregado ou tipo de dado não encontrado")
            return []
        
        print(f"Filtrando snapshot por range {min_value} - {max_value} ({data_type})")
        
        matches = []
        values_dict = self.memory_snapshot[data_type]
        
        for address, value in values_dict.items():
            if min_value <= value <= max_value:
                matches.append((address, value))
        
        print(f"Encontrados {len(matches)} matches no range")
        return matches
    
    def compare_snapshots(self, old_snapshot_file, new_snapshot_data=None):
        """Compara dois snapshots para encontrar valores que mudaram"""
        if new_snapshot_data is None:
            new_snapshot_data = self.memory_snapshot
        
        if not new_snapshot_data:
            print("Nenhum snapshot atual disponível")
            return {}
        
        # Carregar snapshot antigo
        try:
            with open(old_snapshot_file, 'rb') as f:
                old_snapshot = pickle.load(f)['data']
        except Exception as e:
            print(f"Erro ao carregar snapshot antigo: {e}")
            return {}
        
        print("Comparando snapshots...")
        
        changes = {}
        
        for data_type in new_snapshot_data:
            if data_type not in old_snapshot:
                continue
                
            changes[data_type] = {
                'changed': [],  # (endereço, valor_antigo, valor_novo)
                'new': [],      # (endereço, valor)
                'removed': []   # (endereço, valor)
            }
            
            old_values = old_snapshot[data_type]
            new_values = new_snapshot_data[data_type]
            
            # Valores que mudaram
            for addr in old_values:
                if addr in new_values:
                    if old_values[addr] != new_values[addr]:
                        changes[data_type]['changed'].append((addr, old_values[addr], new_values[addr]))
                else:
                    changes[data_type]['removed'].append((addr, old_values[addr]))
            
            # Valores novos
            for addr in new_values:
                if addr not in old_values:
                    changes[data_type]['new'].append((addr, new_values[addr]))
            
            print(f"{data_type.upper()}: {len(changes[data_type]['changed'])} mudaram, "
                  f"{len(changes[data_type]['new'])} novos, "
                  f"{len(changes[data_type]['removed'])} removidos")
        
        return changes

    # ... (resto dos métodos anteriores permanecem iguais)
    
    def scan_for_value(self, value, data_type='int'):
        """Escaneia TODA a memória do processo procurando por um valor específico"""
        results = []
        
        # Obter TODAS as regiões de memória do processo
        regions = self.get_all_memory_regions()
        total_size = sum(region['size'] for region in regions)
        
        print(f"Encontradas {len(regions)} regiões de memória")
        print(f"Tamanho total a escanear: {total_size / (1024*1024):.2f} MB")
        print("Iniciando scan completo da memória...")
        
        scanned_size = 0
        start_time = time.time()
        
        for i, region in enumerate(regions):
            try:
                base_addr = region['base']
                size = region['size']
                
                # Verificar se os valores são válidos
                if base_addr is None or size is None or size <= 0:
                    continue
                
                # Mostrar progresso
                progress = (i + 1) / len(regions) * 100
                print(f"[{progress:5.1f}%] Região {i+1}/{len(regions)}: 0x{base_addr:08X} ({size:,} bytes)")
                
                # Ler a região inteira (sem limitação de tamanho)
                data = self.read_memory(base_addr, size)
                if not data:
                    continue
                
                scanned_size += len(data)
                
                # Procurar pelo valor na região
                if data_type == 'int':
                    pattern = struct.pack('<i', value)
                elif data_type == 'float':
                    pattern = struct.pack('<f', value)
                elif data_type == 'double':
                    pattern = struct.pack('<d', value)
                elif data_type == 'short':
                    pattern = struct.pack('<h', value)
                elif data_type == 'byte':
                    pattern = struct.pack('<B', value)
                else:
                    pattern = value.encode() if isinstance(value, str) else value
                
                # Buscar todas as ocorrências na região
                offset = 0
                region_matches = 0
                while True:
                    pos = data.find(pattern, offset)
                    if pos == -1:
                        break
                    results.append(base_addr + pos)
                    region_matches += 1
                    offset = pos + 1
                
                if region_matches > 0:
                    print(f"  ✓ {region_matches} matches encontrados nesta região")
                    
            except Exception as e:
                print(f"  ✗ Erro ao escanear região: {e}")
                continue
        
        elapsed_time = time.time() - start_time
        print(f"\nScan completo!")
        print(f"Tempo decorrido: {elapsed_time:.2f} segundos")
        print(f"Memória escaneada: {scanned_size / (1024*1024):.2f} MB")
        
        return results
        
    def get_all_memory_regions(self):
        """Obtém TODAS as regiões de memória do processo (sem limitações)"""
        regions = []
        
        if not self.handle:
            return regions
            
        # Estrutura MEMORY_BASIC_INFORMATION
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)
            ]
        
        # Constantes de estado e proteção
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        MEM_FREE = 0x10000
        
        # Todas as proteções que permitem leitura
        PAGE_NOACCESS = 0x01
        PAGE_READONLY = 0x02
        PAGE_READWRITE = 0x04
        PAGE_WRITECOPY = 0x08
        PAGE_EXECUTE = 0x10
        PAGE_EXECUTE_READ = 0x20
        PAGE_EXECUTE_READWRITE = 0x40
        PAGE_EXECUTE_WRITECOPY = 0x80
        PAGE_GUARD = 0x100
        PAGE_NOCACHE = 0x200
        PAGE_WRITECOMBINE = 0x400
        
        # Proteções legíveis (incluindo mais tipos)
        readable_protections = [
            PAGE_READONLY, 
            PAGE_READWRITE, 
            PAGE_WRITECOPY,
            PAGE_EXECUTE_READ, 
            PAGE_EXECUTE_READWRITE, 
            PAGE_EXECUTE_WRITECOPY
        ]
        
        # Determinar se é processo 64-bit ou 32-bit
        is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8
        max_address = 0x7FFFFFFFFFFF if is_64bit else 0x7FFFFFFF
        
        address = 0
        print("Mapeando todas as regiões de memória...")
        
        while address < max_address:
            mbi = MEMORY_BASIC_INFORMATION()
            result = ctypes.windll.kernel32.VirtualQueryEx(
                self.handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            )
            
            if result == 0:
                break
            
            # Converter BaseAddress para int
            base_addr = mbi.BaseAddress
            if base_addr is not None:
                base_addr = int(base_addr)
            
            # Incluir TODAS as regiões commitadas e legíveis
            # Removendo limitações de tamanho e sendo mais permissivo
            if (mbi.State == MEM_COMMIT and 
                mbi.Protect in readable_protections and 
                not (mbi.Protect & PAGE_GUARD) and  # Excluir apenas páginas com GUARD
                mbi.RegionSize > 0 and
                base_addr is not None):
                
                # SEM limitação de tamanho - pegar a região inteira
                regions.append({
                    'base': base_addr,
                    'size': mbi.RegionSize,  # Tamanho real da região
                    'protect': mbi.Protect,
                    'type': mbi.Type
                })
            
            # Avançar para próxima região
            if mbi.RegionSize > 0:
                address = (mbi.BaseAddress or 0) + mbi.RegionSize
            else:
                address += 0x1000  # Avançar 4KB se RegionSize for 0
                
        print(f"Mapeamento concluído: {len(regions)} regiões válidas encontradas")
        
        # Mostrar estatísticas das regiões
        total_size = sum(region['size'] for region in regions)
        print(f"Tamanho total das regiões: {total_size / (1024*1024):.2f} MB")
        
        return regions
    
    def scan_multiple_types(self, value):
        """Escaneia o valor em múltiplos tipos de dados"""
        print(f"Escaneando valor {value} em múltiplos formatos...")
        
        results = {}
        data_types = ['int', 'float', 'short', 'byte']
        
        for data_type in data_types:
            try:
                print(f"\n--- Escaneando como {data_type.upper()} ---")
                matches = self.scan_for_value(value, data_type)
                results[data_type] = matches
                print(f"Encontrados {len(matches)} matches para {data_type}")
            except Exception as e:
                print(f"Erro ao escanear como {data_type}: {e}")
                results[data_type] = []
        
        return results
        
    def close(self):
        if self.handle:
            ctypes.windll.kernel32.CloseHandle(self.handle)


if __name__ == "__main__":
    print("=== Memory Scanner - Scan Completo ===")
    
    # Listar processos disponíveis
    print("\nProcessos disponíveis:")
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            processes.append((proc.info['pid'], proc.info['name']))
        except:
            continue
    
    # Mostrar alguns processos comuns
    common_processes = [p for p in processes if p[1] in ['notepad.exe', 'calc.exe', 'calculator.exe', 'mspaint.exe']]
    if common_processes:
        print("Processos comuns encontrados:")
        for pid, name in common_processes:
            print(f"  {name} (PID: {pid})")
    
    process_name = input("\nDigite o nome do processo: ").strip()
    scanner = MemoryScanner(process_name)
    
    if not scanner.process:
        print(f"Processo '{process_name}' não encontrado!")
        exit()
        
    print(f"Processo encontrado: {scanner.process.info['name']} (PID: {scanner.process.pid})")
    
    if scanner.open_process():
        print("Processo aberto com sucesso!")
        
        try:
            print("\nOpções de scan:")
            print("1. Scan com valor específico")
            print("2. Scan múltiplos tipos")
            print("3. SCAN TOTAL (sem valor inicial) - CRIA SNAPSHOT")
            print("4. Carregar snapshot e filtrar")
            print("5. Comparar snapshots")
            
            choice = input("Escolha (1-5): ").strip()
            
            if choice == "3":
                # Scan total sem valor inicial
                data_types = input("Tipos de dados (int,float,short,byte) [int]: ").strip()
                if not data_types:
                    data_types = ['int']
                else:
                    data_types = [dt.strip() for dt in data_types.split(',')]
                
                snapshot = scanner.full_memory_scan(data_types)
                
                if snapshot:
                    print("\n=== SNAPSHOT CRIADO ===")
                    print("Agora você pode:")
                    print("- Filtrar por valor específico")
                    print("- Filtrar por range de valores")
                    print("- Comparar com snapshots futuros")
                    
                    # Opção de filtrar imediatamente
                    filter_now = input("\nFiltrar snapshot agora? (s/n): ").strip().lower()
                    if filter_now == 's':
                        data_type = input("Tipo de dado para filtrar: ").strip() or 'int'
                        value = int(input("Valor para procurar: "))
                        
                        matches = scanner.filter_snapshot_by_value(value, data_type)
                        if matches:
                            print(f"\nEncontrados {len(matches)} matches:")
                            for i, (addr, val) in enumerate(matches[:10]):
                                print(f"  0x{addr:08X}: {val}")
                            if len(matches) > 10:
                                print(f"  ... e mais {len(matches) - 10}")
            
            elif choice == "4":
                # Carregar e filtrar snapshot
                filename = input("Nome do arquivo de snapshot: ").strip()
                if scanner.load_snapshot(filename):
                    data_type = input("Tipo de dado para filtrar: ").strip() or 'int'
                    value = int(input("Valor para procurar: "))
                    
                    matches = scanner.filter_snapshot_by_value(value, data_type)
                    if matches:
                        print(f"\nEncontrados {len(matches)} matches:")
                        for i, (addr, val) in enumerate(matches[:10]):
                            print(f"  0x{addr:08X}: {val}")
                        if len(matches) > 10:
                            print(f"  ... e mais {len(matches) - 10}")
            
            elif choice == "5":
                # Comparar snapshots
                old_file = input("Arquivo do snapshot antigo: ").strip()
                print("Criando novo snapshot para comparação...")
                
                data_types = ['int']  # Simplificado para comparação
                new_snapshot = scanner.full_memory_scan(data_types, save_to_file=False)
                
                if new_snapshot:
                    changes = scanner.compare_snapshots(old_file, new_snapshot)
                    
                    print("\n=== MUDANÇAS DETECTADAS ===")
                    for data_type, change_data in changes.items():
                        if change_data['changed']:
                            print(f"\n{data_type.upper()} - Valores que mudaram:")
                            for addr, old_val, new_val in change_data['changed'][:10]:
                                print(f"  0x{addr:08X}: {old_val} → {new_val}")
            
            elif choice in ["1", "2"]:
                # Scan tradicional com valor
                value = int(input("Digite o valor para procurar: "))
                
                if choice == "2":
                    # Scan em múltiplos tipos
                    all_results = scanner.scan_multiple_types(value)
                    
                    print(f"\n=== RESULTADOS FINAIS ===")
                    total_matches = 0
                    for data_type, addresses in all_results.items():
                        if addresses:
                            total_matches += len(addresses)
                            print(f"\n{data_type.upper()}: {len(addresses)} matches")
                            for i, addr in enumerate(addresses[:5]):
                                print(f"  0x{addr:08X}")
                            if len(addresses) > 5:
                                print(f"  ... e mais {len(addresses) - 5}")
                    
                    print(f"\nTotal geral: {total_matches} matches encontrados")
                    
                else:
                    # Scan simples
                    data_type = input("Tipo de dado (int/float/short/byte) [int]: ").strip() or 'int'
                    
                    print(f"\n⚠️  ATENÇÃO: Scan completo pode demorar vários minutos!")
                    confirm = input("Continuar? (s/n): ").strip().lower()
                    
                    if confirm == 's':
                        addresses = scanner.scan_for_value(value, data_type)
                        
                        if addresses:
                            print(f"\n✓ Valor {value} encontrado em {len(addresses)} endereços:")
                            for i, addr in enumerate(addresses[:20]):
                                print(f"  [{i+1:3d}] 0x{addr:08X}")
                            if len(addresses) > 20:
                                print(f"  ... e mais {len(addresses) - 20} endereços")
                        else:
                            print(f"\n✗ Valor {value} não encontrado em toda a memória do processo")
                
        except ValueError:
            print("Erro: Digite apenas números!")
        except KeyboardInterrupt:
            print("\nScan interrompido pelo usuário")
        except Exception as e:
            print(f"Erro durante o scan: {e}")
        finally:
            scanner.close()
            print("Scanner fechado.")
    else:
        print("Falha ao abrir o processo! Execute como administrador.")