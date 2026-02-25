import hashlib
import time
import json
from geopy.distance import geodesic  # For GPS tolerance
from typing import List, Tuple

class GuardianFingerprint:
    """
    Phone-side environmental fingerprint scanner for anti-spoofing.
    Fuses GPS, WiFi RSSI, Bluetooth beacons, IMU wobble, and obstacle density.
    Integrates with 4-digit exchange for dynamic key salting.
    """

    def __init__(self, memorable_gps: Tuple[float, float], tolerance_ft: float = 3.0):
        self.memorable_gps = memorable_gps  # Static seed (restaurant pin)
        self.tolerance_m = tolerance_ft * 0.3048  # Convert ft to meters for geodesic
        self.baseline_hash = None  # Set after first successful scan
        self.last_scan_time = 0

    def scan_environment(self, current_gps: Tuple[float, float], wifi_rssi: List[Tuple[int, str]],
                         bt_beacons: List[Tuple[str, int]], imu_wobble: float = 0.0, obstacle_density: float = 0.5):
        """
        Scan real-time signals for fingerprint.
        - wifi_rssi: [(rssi_dbm, ssid), ...] from phone WiFi scan
        - bt_beacons: [(mac, rssi_dbm), ...] from BLE discovery (e.g., nearby vehicles/devices)
        - imu_wobble: Float from accelerometer (movement variance; 0 = still)
        - obstacle_density: ML-inferred (0-1; e.g., from maps API or camera edge detect for clutter)
        """
        # Check proximity to memorable place
        dist = geodesic(self.memorable_gps, current_gps).meters
        if dist > self.tolerance_m:
            raise ValueError(f"Outside 3ft radius: {dist:.2f}m drift detected - access denied.")

        # Build dynamic snapshot (sort for consistency against scan order)
        snapshot = {
            'gps': current_gps,
            'wifi': sorted(wifi_rssi, key=lambda x: x[0]),  # Sort by RSSI descending
            'bt': sorted(bt_beacons, key=lambda x: x[1]),
            'imu': imu_wobble,
            'density': obstacle_density,
            'earth_offset': time.time() % 86400 / 3600  # Hourly Earth rotation proxy for time-variance
        }
        return json.dumps(snapshot, sort_keys=True).encode()

    def compute_fingerprint_hash(self, snapshot_bytes: bytes):
        """Hash the snapshot for mismatch detection and salting."""
        return hashlib.sha256(snapshot_bytes).hexdigest()[:16]  # Truncated for lightness; full for prod

    def validate_and_update(self, snapshot_bytes: bytes):
        """Check against baseline; update if clean (adapts to small daily changes)."""
        current_hash = self.compute_fingerprint_hash(snapshot_bytes)
        if self.baseline_hash and not self._fuzzy_match(current_hash, self.baseline_hash):
            raise ValueError("Environmental mismatch - possible spoof (e.g., truck shifted unexpectedly).")
        
        # Update baseline for next (tolerance for minor drifts like one car moving)
        self.baseline_hash = current_hash
        self.last_scan_time = time.time()
        return current_hash

    def _fuzzy_match(self, hash1: str, hash2: str, threshold: float = 0.9) -> bool:
        """Simple fuzzy compare (e.g., Hamming distance proxy for small drifts)."""
        diff = sum(c1 != c2 for c1, c2 in zip(hash1, hash2))
        similarity = 1 - (diff / len(hash1))
        return similarity >= threshold  # Tune based on testing

    def salt_4digit_rotation(self, current_4digit: str, fingerprint_hash: str) -> str:
        """Use fingerprint as salt for next 4-digit in exchange (ties to previous snippet)."""
        salted = hashlib.sha256((current_4digit + fingerprint_hash).encode()).hexdigest()
        next_digit = int(salted, 16) % 10000
        return f"{next_digit:04d}"

# Mock usage (simulate phone scan)
if __name__ == "__main__":
    guardian = GuardianFingerprint((37.7749, -122.4194))  # Memorable restaurant pin
    
    # Mock today's scan (truck in spot, school bus nearby)
    wifi = [(-60, "HomeNet"), (-70, "NeighborWiFi")]
    bt = [("TruckMAC:AA:BB", -50), ("SchoolBusMAC:CC:DD", -80)]
    snapshot = guardian.scan_environment((37.7749, -122.4194), wifi, bt, imu_wobble=0.1, obstacle_density=0.6)
    
    try:
        fp_hash = guardian.validate_and_update(snapshot)
        next_4digit = guardian.salt_4digit_rotation("1234", fp_hash)  # Feed to exchange
        print(f"Validated! Next salted 4-digit: {next_4digit}")
    except ValueError as e:
        print(f"Deny/Purge: {e}")

    # Mock spoof attempt (truck missing, density off)
    wifi_spoof = [(-60, "HomeNet"), (-75, "FakeNeighbor")]  # Slight change
    bt_spoof = [("FakeMAC:EE:FF", -50)]  # Missing bus
    snapshot_spoof = guardian.scan_environment((37.7749, -122.4194), wifi_spoof, bt_spoof, 0.1, 0.4)
    try:
        guardian.validate_and_update(snapshot_spoof)
    except ValueError as e:
        print(f"Spoof caught: {e}")