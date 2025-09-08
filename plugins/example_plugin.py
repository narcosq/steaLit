"""
Example SteaLit Plugin
This shows how to create custom plugins for SteaLit
"""

import os
from pathlib import Path
from typing import List
import sys
import subprocess

sys.path.append(str(Path(__file__).parent.parent / "modules"))
from plugin_system import SteaLitPlugin

class ExamplePlugin(SteaLitPlugin):
    """Example plugin that demonstrates the plugin interface"""
    
    @property
    def name(self) -> str:
        return "Example Plugin"
    
    @property
    def description(self) -> str:
        return "Example plugin showing how to create custom data collectors"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def dependencies(self) -> List[str]:
        return []
    
    @property
    def enabled_by_default(self) -> bool:
        return False
    
    def collect_data(self, output_dir: Path) -> bool:
        """Collect example data"""
        try:
            output_file = output_dir / "example_data.txt"
            
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("Example Plugin Output\n")
                f.write("=" * 30 + "\n\n")
                
                f.write("Environment Variables:\n")
                f.write("-" * 20 + "\n")
                for key, value in os.environ.items():
                    if not key.startswith("_"):
                        f.write(f"{key}={value}\n")
                
                f.write("\n")
                
                f.write("System Information:\n")
                f.write("-" * 20 + "\n")
                try:
                    result = subprocess.run(["systeminfo"], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        f.write(result.stdout)
                    else:
                        f.write("Could not get system info\n")
                except Exception as e:
                    f.write(f"Error getting system info: {e}\n")
            
            print(f"[Example Plugin] Data saved to: {output_file}")
            return True
            
        except Exception as e:
            print(f"[Example Plugin] Error: {e}")
            return False
    
    def get_output_files(self, output_dir: Path) -> List[Path]:
        """Return list of files created by this plugin"""
        output_file = output_dir / "example_data.txt"
        return [output_file] if output_file.exists() else []


class NetworkInfoPlugin(SteaLitPlugin):
    """Plugin that collects network information"""
    
    @property
    def name(self) -> str:
        return "Network Info"
    
    @property
    def description(self) -> str:
        return "Collects network configuration and connection information"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def enabled_by_default(self) -> bool:
        return False
    
    def collect_data(self, output_dir: Path) -> bool:
        """Collect network data"""
        try:
            output_file = output_dir / "network_info.txt"
            
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("Network Information\n")
                f.write("=" * 30 + "\n\n")
                
                f.write("IP Configuration:\n")
                f.write("-" * 20 + "\n")
                try:
                    result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        f.write(result.stdout)
                    else:
                        f.write("Could not get IP config\n")
                except Exception as e:
                    f.write(f"Error getting IP config: {e}\n")
                
                f.write("\n\n")
                
                f.write("Active Network Connections:\n")
                f.write("-" * 30 + "\n")
                try:
                    result = subprocess.run(["netstat", "-an"], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        f.write(result.stdout)
                    else:
                        f.write("Could not get network connections\n")
                except Exception as e:
                    f.write(f"Error getting network connections: {e}\n")
            
            print(f"[Network Info Plugin] Data saved to: {output_file}")
            return True
            
        except Exception as e:
            print(f"[Network Info Plugin] Error: {e}")
            return False
