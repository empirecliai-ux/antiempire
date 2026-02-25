import pytest
import time
from security.system_guardian import SystemGuardian, SystemState, CodeRotator

@pytest.fixture
def rotator():
    return CodeRotator(secret_seed="empire_secret_seed")

def test_code_rotation_24h(rotator):
    base_time = 1600000000.0
    code1 = rotator.get_current_code(base_time)

    # Same day, same code
    code2 = rotator.get_current_code(base_time + 3600) # +1 hour
    assert code1 == code2

    # Next day, different code
    code3 = rotator.get_current_code(base_time + 86401) # +24h + 1s
    assert code1 != code3

def test_process_rendezvous(rotator):
    active = ["systemd", "guardian_core", "network_manager"]
    assert rotator.check_process_rendezvous("guardian_core", "network_manager", active) is True
    assert rotator.check_process_rendezvous("guardian_core", "malware_exe", active) is False

@pytest.fixture
def guardian():
    initial_state = SystemState(
        os_type="Linux",
        version="1.0",
        file_hashes={"/boot/vmlinuz": "hash_linux_kernel", "/etc/shadow": "hash_linux_shadow"},
        partition_layout="sda1:boot,sda2:root"
    )
    return SystemGuardian(known_good_state=initial_state)

def test_integrity_check_pass(guardian):
    current = SystemState(
        os_type="Linux",
        version="1.0",
        file_hashes={"/boot/vmlinuz": "hash_linux_kernel", "/etc/shadow": "hash_linux_shadow"},
        partition_layout="sda1:boot,sda2:root"
    )
    valid, msg = guardian.validate_integrity(current)
    assert valid is True
    assert "Verified" in msg

def test_integrity_check_fail_file_mod(guardian):
    current = SystemState(
        os_type="Linux",
        version="1.0",
        file_hashes={"/boot/vmlinuz": "hash_MALICIOUS_kernel", "/etc/shadow": "hash_linux_shadow"},
        partition_layout="sda1:boot,sda2:root"
    )
    valid, msg = guardian.validate_integrity(current)
    assert valid is False
    assert "Integrity Violation" in msg
    assert guardian.trust_score < 100

def test_handle_update_event(guardian):
    new_state = SystemState(
        os_type="Linux",
        version="1.1", # Updated
        file_hashes={"/boot/vmlinuz": "new_hash_kernel", "/etc/shadow": "hash_linux_shadow"}
    )

    # Directly validating this state would fail integrity check against old baseline
    valid, _ = guardian.validate_integrity(new_state)
    assert valid is False

    # But handling it as an event should update baseline
    guardian.handle_system_event("OS_UPDATE", new_state)
    assert guardian.known_good_state.version == "1.1"
    assert guardian.trust_score == 100.0

    # Now validation should pass
    valid, _ = guardian.validate_integrity(new_state)
    assert valid is True

def test_handle_recovery_reset(guardian):
    reset_state = SystemState(
        os_type="Linux",
        version="1.0_fresh",
        file_hashes={"/boot/vmlinuz": "hash_linux_kernel_fresh"},
        partition_layout="sda1:recovery"
    )

    guardian.handle_system_event("RECOVERY_RESET", reset_state)
    assert guardian.known_good_state.version == "1.0_fresh"
    assert guardian.trust_score == 50.0 # Reduced trust
