import hashlib
import time
import uuid
import math
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set

@dataclass
class SystemState:
    os_type: str  # Windows, MacOS, Linux, Android, iOS
    version: str
    file_hashes: Dict[str, str] = field(default_factory=dict)
    processes: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    partition_layout: Optional[str] = None

class CodeRotator:
    def __init__(self, secret_seed: str):
        self.secret_seed = secret_seed
        self.rotation_interval = 86400  # 24 hours in seconds

    def get_current_code(self, timestamp: float = None) -> str:
        """
        Generates a 4-digit code based on the seed and time window.
        """
        if timestamp is None:
            timestamp = time.time()

        # Calculate time window index
        window_index = int(timestamp // self.rotation_interval)

        # Salt with seed and window
        data = f"{self.secret_seed}:{window_index}"
        hash_val = hashlib.sha256(data.encode()).hexdigest()

        # Convert to 4 digits (0000-9999)
        code_int = int(hash_val, 16) % 10000
        return f"{code_int:04d}"

    def check_process_rendezvous(self, proc_a: str, proc_b: str, active_processes: List[str]) -> bool:
        """
        Checks if two critical processes are running simultaneously to authorize
        a rotation or sensitive action.
        """
        return proc_a in active_processes and proc_b in active_processes

class SystemGuardian:
    def __init__(self, known_good_state: SystemState):
        self.known_good_state = known_good_state
        self.maintenance_mode = False
        self.trust_score = 100.0

        # Mock "Known Good" file sets for different OSes
        self.os_signatures = {
            "Windows": {
                "C:\\Windows\\System32\ntoskrnl.exe": "hash_win_kernel",
                "C:\\Program Files\\Common Files": "hash_win_common"
            },
            "MacOS": {
                "/System/Library/CoreServices": "hash_mac_core",
                "/usr/bin/sudo": "hash_mac_sudo"
            },
            "Linux": {
                "/boot/vmlinuz": "hash_linux_kernel",
                "/etc/shadow": "hash_linux_shadow"
            },
            "Android": {
                "/system/framework": "hash_android_framework",
                "/sbin/su": "hash_android_su" # Root check?
            },
            "iOS": {
                "/System/Library/CoreServices": "hash_ios_core"
            }
        }

    def scan_system_mock(self, os_type: str, new_files: Dict[str, str] = None) -> SystemState:
        """
        Simulates scanning the system.
        """
        base_files = self.os_signatures.get(os_type, {}).copy()
        if new_files:
            base_files.update(new_files)

        return SystemState(
            os_type=os_type,
            version=self.known_good_state.version, # Assume same unless update event
            file_hashes=base_files,
            processes=["proc_guardian_core", "proc_system_monitor"],
            timestamp=time.time()
        )

    def validate_integrity(self, current_state: SystemState) -> Tuple[bool, str]:
        """
        Compares current state against known good state.
        """
        if self.maintenance_mode:
            return True, "Maintenance Mode: Checks skipped"

        # 1. OS Consistency
        if current_state.os_type != self.known_good_state.os_type:
             return False, "CRITICAL: OS Type changed (Dual Boot / Reimage?)"

        # 2. File Integrity
        mismatches = []
        for file, known_hash in self.known_good_state.file_hashes.items():
            current_hash = current_state.file_hashes.get(file)
            if current_hash != known_hash:
                mismatches.append(file)

        if mismatches:
            self.trust_score -= (len(mismatches) * 20)
            return False, f"Integrity Violation: Modified files {mismatches}"

        # 3. Partition Check (Mock)
        if current_state.partition_layout and self.known_good_state.partition_layout:
             if current_state.partition_layout != self.known_good_state.partition_layout:
                 return False, "Partition Layout Changed"

        return True, "System Integrity Verified"

    def handle_system_event(self, event_type: str, new_state: SystemState = None):
        """
        Handles legitimate system events like Updates, Recovery, Reset.
        """
        print(f"Handling System Event: {event_type}")

        if event_type == "OS_UPDATE":
            # Legit update: Update known good state without penalizing trust
            if new_state:
                print(f"Updating baseline from {self.known_good_state.version} to {new_state.version}")
                self.known_good_state = new_state
                self.trust_score = 100.0 # Restore trust on verified update
            return True

        elif event_type == "RECOVERY_RESET":
            # Factory reset / Recovery: Clear old data but re-establish baseline
            print("System Reset Detected. Clearing old IP/Trust associations.")
            if new_state:
                self.known_good_state = new_state
                self.trust_score = 50.0 # Cautionary trust level after reset
            return True

        elif event_type == "PARTITION_CHANGE":
            # Disk management: Accept if authenticated
            print("Partition change authorized.")
            if new_state and new_state.partition_layout:
                 self.known_good_state.partition_layout = new_state.partition_layout
            return True

        else:
            print("Unknown event type")
            return False
