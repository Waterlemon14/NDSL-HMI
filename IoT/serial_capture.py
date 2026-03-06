#!/usr/bin/env python3
"""Capture benchmark results from Serial and save to results.txt."""

import sys
import os
import glob
import serial
import serial.tools.list_ports
import argparse

BAUD_RATE = 115200
START_MARKER = "===== BENCHMARK START ====="
END_MARKER = "===== BENCHMARK COMPLETE ====="


def find_serial_port():
    """Auto-detect serial port of microcontroller."""
    patterns = ["/dev/cu.usbserial-*", "/dev/cu.SLAB_USBtoUART*", "/dev/cu.wchusbserial-*"]
    for pattern in patterns:
        ports = glob.glob(pattern)
        if ports:
            return ports[0]
    
    target_keywords = ["USB", "UART", "CP210", "CH340", "FT232"]
    ports = serial.tools.list_ports.comports()

    for port in ports:
        for keyword in target_keywords:
            if keyword.lower() in port.description.lower():
                return port.device

    return None


def main():
    parser = argparse.ArgumentParser(description="NDSL-HMI Testing Serial Port Capture Tool")

    parser.add_argument(
        "device", 
        type=str, 
        choices=["esp32", "esp8266", "pico"],
        help="The type of microcontroller you are testing."
    )

    parser.add_argument(
        "-p",
        "--port",
        type=str,
        help="The serial port of the microcontroller"
    )

    args = parser.parse_args()

    port = args.port or find_serial_port()
    device = args.device

    if not port:
        print("Error: No serial port detected.")
        sys.exit(1)

    print(f"Connecting to {port} at {BAUD_RATE} baud...")
    try:
        ser = serial.Serial(port, BAUD_RATE, timeout=1)

        if device == "esp8266":
            ser.setDTR(False)
            ser.setRTS(False)
        
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
                continue

            if capturing:
                if END_MARKER in line:
                    break
                if "," in line:
                    captured_lines.append(line)

    except KeyboardInterrupt:
        print("\nAborted by user.")
    finally:
        ser.close()

    if captured_lines:
        out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"results_{device}.csv")
        with open(out_path, "w") as f:
            f.write("TestType,Iteration,Elapsed_ms,Result\n")
            f.write("\n".join(captured_lines) + "\n")
        print(f"\nResults saved to {out_path}")
    else:
        print("\nNo benchmark results captured.")


if __name__ == "__main__":
    main()