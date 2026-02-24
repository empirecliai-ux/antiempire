import pytest
import time
import uuid
import hashlib
from unittest.mock import patch, MagicMock
from security.location_verifier import LocationVerifier, LocationProfile, client_exchange

@pytest.fixture
def base_profile():
    return LocationProfile(
        latitude=37.7749,
        longitude=-122.4194,
        wifi_ssids=["Home_Wifi", "Neighbor_Wifi", "Public_Net"],
        bt_macs=["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"],
        imu_wobble=0.2,
        timestamp=time.time(),
        nonce="original_nonce"
    )

@pytest.fixture
def verifier(base_profile):
    return LocationVerifier(stored_profile=base_profile, tolerance_ft=20.0)

def test_collect_sensor_data(verifier):
    data = verifier.collect_sensor_data()
    assert isinstance(data, LocationProfile)
    assert data.timestamp > 0
    assert data.nonce != verifier.stored_profile.nonce
    # Check drift is small
    assert abs(data.latitude - verifier.stored_profile.latitude) < 0.001
    assert abs(data.longitude - verifier.stored_profile.longitude) < 0.001

def test_fuzzy_match_valid(verifier, base_profile):
    # Same location, slightly different time/nonce
    current = LocationProfile(
        latitude=base_profile.latitude,
        longitude=base_profile.longitude,
        wifi_ssids=base_profile.wifi_ssids,
        bt_macs=base_profile.bt_macs,
        imu_wobble=0.2,
        timestamp=time.time(),
        nonce="new_nonce"
    )
    match, reason = verifier.is_fuzzy_match(current)
    assert match is True
    assert reason == "Match confirmed"

def test_fuzzy_match_small_drift(verifier, base_profile):
    # ~5ft drift
    # 1 degree lat approx 364000 ft. 0.00001 deg is ~3.6 ft
    current = LocationProfile(
        latitude=base_profile.latitude + 0.00001,
        longitude=base_profile.longitude + 0.00001,
        wifi_ssids=base_profile.wifi_ssids,
        bt_macs=base_profile.bt_macs,
        imu_wobble=0.2
    )
    match, reason = verifier.is_fuzzy_match(current)
    assert match is True

def test_fuzzy_match_large_drift(verifier, base_profile):
    # Large drift
    current = LocationProfile(
        latitude=base_profile.latitude + 0.01, # ~3600 ft
        longitude=base_profile.longitude,
        wifi_ssids=base_profile.wifi_ssids,
        bt_macs=base_profile.bt_macs,
        imu_wobble=0.2
    )
    match, reason = verifier.is_fuzzy_match(current)
    assert match is False
    assert "Location mismatch" in reason

def test_fuzzy_match_sensor_mismatch(verifier, base_profile):
    # Totally different sensors
    current = LocationProfile(
        latitude=base_profile.latitude,
        longitude=base_profile.longitude,
        wifi_ssids=["Unknown_Net"],
        bt_macs=["99:88:77:66:55:44"],
        imu_wobble=0.2
    )
    match, reason = verifier.is_fuzzy_match(current)
    assert match is False
    assert "Sensor mismatch" in reason

def test_fuzzy_match_static_imu(verifier, base_profile):
    # Static IMU (spoofing)
    current = LocationProfile(
        latitude=base_profile.latitude,
        longitude=base_profile.longitude,
        wifi_ssids=base_profile.wifi_ssids,
        bt_macs=base_profile.bt_macs,
        imu_wobble=0.0
    )
    match, reason = verifier.is_fuzzy_match(current)
    assert match is False
    assert "IMU mismatch" in reason

def test_replay_attack_fresh(verifier, base_profile):
    current = LocationProfile(
        latitude=base_profile.latitude,
        longitude=base_profile.longitude,
        timestamp=time.time(),
        nonce="fresh_nonce"
    )
    assert verifier.is_replay_attack(current) is False

def test_replay_attack_stale(verifier, base_profile):
    current = LocationProfile(
        latitude=base_profile.latitude,
        longitude=base_profile.longitude,
        timestamp=time.time() - 100, # Too old
        nonce="fresh_nonce"
    )
    assert verifier.is_replay_attack(current) is True

def test_replay_attack_duplicate_nonce(verifier, base_profile):
    current = LocationProfile(
        latitude=base_profile.latitude,
        longitude=base_profile.longitude,
        timestamp=time.time(),
        nonce=base_profile.nonce # Duplicate
    )
    assert verifier.is_replay_attack(current) is True

def test_client_exchange_success(verifier, base_profile):
    current = LocationProfile(
        latitude=base_profile.latitude,
        longitude=base_profile.longitude,
        wifi_ssids=base_profile.wifi_ssids,
        bt_macs=base_profile.bt_macs,
        imu_wobble=0.2,
        timestamp=time.time(),
        nonce="new_nonce"
    )
    metadata = {}
    pin = "1234"
    result = client_exchange(metadata, pin, verifier, current)

    assert result["status"] == "success"
    assert "fingerprint_hash" in result["metadata"]
    assert "storage_shard" in result["metadata"]

    # Check hash correctness
    expected_data = f"{current.latitude:.4f}{current.longitude:.4f}{sorted(current.wifi_ssids)}{pin}"
    expected_hash = hashlib.sha256(expected_data.encode()).hexdigest()
    assert result["metadata"]["fingerprint_hash"] == expected_hash

def test_client_exchange_fail_location(verifier, base_profile):
    current = LocationProfile(
        latitude=base_profile.latitude + 0.1, # Far away
        longitude=base_profile.longitude,
        imu_wobble=0.2,
        timestamp=time.time(),
        nonce="new_nonce"
    )
    metadata = {}
    pin = "1234"
    result = client_exchange(metadata, pin, verifier, current)

    assert result["status"] == "deny"
    assert result["action"] == "prompt_mfa"

def test_decipher_relocation(verifier):
    fp_hash = "abcdef1234567890"
    path = verifier.decipher_relocation(fp_hash)
    shard_id = hashlib.md5(fp_hash.encode()).hexdigest()[:8]
    assert path == f"/data/shards/{shard_id}"
