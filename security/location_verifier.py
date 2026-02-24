import hashlib
import math
import time
import uuid
import random
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

@dataclass
class LocationProfile:
    latitude: float
    longitude: float
    wifi_ssids: List[str] = field(default_factory=list)
    bt_macs: List[str] = field(default_factory=list)
    imu_wobble: float = 0.0  # Represents movement variance or pattern score
    timestamp: float = field(default_factory=time.time)
    nonce: str = field(default_factory=lambda: str(uuid.uuid4()))

class LocationVerifier:
    def __init__(self, stored_profile: LocationProfile, tolerance_ft: float = 10.0):
        self.stored_profile = stored_profile
        self.tolerance_ft = tolerance_ft
        # Earth radius in feet (approx)
        self.earth_radius_ft = 20902231.0

    def collect_sensor_data(self) -> LocationProfile:
        """
        Mocks the collection of sensor data.
        In a real implementation, this would interface with hardware APIs.
        """
        # Simulate small drift
        lat_drift = random.uniform(-0.00001, 0.00001)
        lon_drift = random.uniform(-0.00001, 0.00001)

        # Simulate Wifi/BT changes (mostly same, some flux)
        wifi = self.stored_profile.wifi_ssids[:]
        if random.random() < 0.1: # 10% chance to lose/gain a network
             if wifi: wifi.pop()
             else: wifi.append(f"new_net_{random.randint(100,999)}")

        bt = self.stored_profile.bt_macs[:]
        if random.random() < 0.1:
             if bt: bt.pop()

        # Simulate IMU wobble (e.g. walking vs sitting)
        wobble = random.uniform(0.1, 0.5)

        return LocationProfile(
            latitude=self.stored_profile.latitude + lat_drift,
            longitude=self.stored_profile.longitude + lon_drift,
            wifi_ssids=wifi,
            bt_macs=bt,
            imu_wobble=wobble,
            timestamp=time.time(),
            nonce=str(uuid.uuid4())
        )

    def _haversine_distance_ft(self, lat1, lon1, lat2, lon2):
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat / 2) * math.sin(dlat / 2) +             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *             math.sin(dlon / 2) * math.sin(dlon / 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return self.earth_radius_ft * c

    def is_fuzzy_match(self, current: LocationProfile) -> Tuple[bool, str]:
        """
        Checks if the current profile matches the stored profile within tolerance.
        Returns (is_match, reason)
        """
        # 1. Location Drift
        dist = self._haversine_distance_ft(
            current.latitude, current.longitude,
            self.stored_profile.latitude, self.stored_profile.longitude
        )
        if dist > self.tolerance_ft:
            return False, f"Location mismatch: moved {dist:.2f}ft (limit {self.tolerance_ft}ft)"

        # 2. Wifi/BT Overlap (Jaccard Index)
        wifi_match = self._calculate_jaccard(current.wifi_ssids, self.stored_profile.wifi_ssids)
        bt_match = self._calculate_jaccard(current.bt_macs, self.stored_profile.bt_macs)

        # Combined sensor score (weighted)
        sensor_score = (wifi_match * 0.6) + (bt_match * 0.4)
        if sensor_score < 0.8: # Allow 20% variance
            return False, f"Sensor mismatch: score {sensor_score:.2f} < 0.8"

        # 3. IMU Wobble (Anti-SDR/Static check)
        # If wobble is too low (perfectly still), it might be a spoof or emulator
        if current.imu_wobble < 0.01:
             return False, "IMU mismatch: device too static (possible spoof)"

        return True, "Match confirmed"

    def _calculate_jaccard(self, list1, list2):
        s1 = set(list1)
        s2 = set(list2)
        if not s1 and not s2: return 1.0 # Both empty matches
        return len(s1.intersection(s2)) / len(s1.union(s2))

    def is_replay_attack(self, current: LocationProfile, max_age_seconds: float = 60.0) -> bool:
        """
        Checks for replay attacks using timestamp and nonce.
        """
        # Time check
        if time.time() - current.timestamp > max_age_seconds:
            return True # Too old

        # In a real system, we'd check if nonce was used recently in a DB
        # Here we just check if it's identical to stored (which shouldn't happen for new requests)
        if current.nonce == self.stored_profile.nonce:
             return True

        return False

    def generate_fingerprint_hash(self, profile: LocationProfile, pin: str) -> str:
        """
        Salts the PIN with the location fingerprint.
        """
        data = f"{profile.latitude:.4f}{profile.longitude:.4f}{sorted(profile.wifi_ssids)}{pin}"
        return hashlib.sha256(data.encode()).hexdigest()

    def handle_fallback(self, reason: str):
        """
        Handles verification failure.
        """
        print(f"Verification Failed: {reason}")
        # Logic to queue changes (read-only) or prompt for re-pin
        return {
            "status": "deny",
            "action": "prompt_mfa", # e.g. FaceID
            "message": "Significant location change detected. Please re-authenticate."
        }

    def decipher_relocation(self, fp_hash: str):
        """
        Calculates new shard path based on hash.
        """
        shard_id = hashlib.md5(fp_hash.encode()).hexdigest()[:8]
        new_path = f"/data/shards/{shard_id}"
        print(f"Relocating data to: {new_path}")
        return new_path

def client_exchange(metadata: Dict, pin: str, verifier: LocationVerifier, current_profile: LocationProfile):
    """
    Integrates the fingerprint hash into the client exchange metadata.
    """
    # 1. Verify Location
    is_match, reason = verifier.is_fuzzy_match(current_profile)
    if not is_match:
        return verifier.handle_fallback(reason)

    # 2. Check Replay
    if verifier.is_replay_attack(current_profile):
        return verifier.handle_fallback("Replay attack detected")

    # 3. Generate Hash & Salt
    fp_hash = verifier.generate_fingerprint_hash(current_profile, pin)

    # 4. Update Metadata
    metadata['fingerprint_hash'] = fp_hash

    # 5. Decipher Relocation (Post-success)
    new_shard = verifier.decipher_relocation(fp_hash)
    metadata['storage_shard'] = new_shard

    return {"status": "success", "metadata": metadata}
