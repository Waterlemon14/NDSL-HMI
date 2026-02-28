#!/usr/bin/env python3
"""Capture ESP32 benchmark results from Serial and save to results.txt."""

import sys
import os
import glob
import serial

BAUD_RATE = 115200
START_MARKER = "===== ESP32 BENCHMARK RESULTS ====="
END_MARKER = "===== BENCHMARK COMPLETE ====="


def find_serial_port():
    """Auto-detect the ESP32 serial port on macOS."""
    patterns = ["/dev/cu.usbserial-*", "/dev/cu.SLAB_USBtoUART*", "/dev/cu.wchusbserial-*"]
    for pattern in patterns:
        ports = glob.glob(pattern)
        if ports:
            return ports[0]
    return None


def main():
    if len(sys.argv) > 1:
        port = sys.argv[1]
    else:
        port = find_serial_port()
        if port is None:
            print("Error: No ESP32 serial port detected.")
            print("Usage: python serial_capture.py [/dev/cu.usbserial-XXXX]")
            sys.exit(1)

    print(f"Connecting to {port} at {BAUD_RATE} baud...")
    try:
        ser = serial.Serial(port, BAUD_RATE, timeout=1)
    except serial.SerialException as e:
        print(f"Error opening serial port: {e}")
        sys.exit(1)

    print("Listening for benchmark output (Ctrl+C to abort)...\n")

    capturing = False
    captured_lines = []

    try:
        while True:
            raw = ser.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            print(line)

            if START_MARKER in line:
                capturing = True
                captured_lines = [line]
                continue

            if capturing:
                captured_lines.append(line)
                if END_MARKER in line:
                    break
    except KeyboardInterrupt:
        print("\nAborted by user.")
    finally:
        ser.close()

    if captured_lines:
        out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.txt")
        with open(out_path, "w") as f:
            f.write("\n".join(captured_lines) + "\n")
        print(f"\nResults saved to {out_path}")
    else:
        print("\nNo benchmark results captured.")


if __name__ == "__main__":
    main()
