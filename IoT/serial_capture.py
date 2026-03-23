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
    out_dir = os.path.dirname(os.path.abspath(__file__))
    header = "TestType,Iteration,Elapsed_ms,Result\n"

    # Per-test buffers and counters
    test_lines = {}    # test_type -> list of pending lines
    test_files = {}    # test_type -> number of files already saved
    SAVE_EVERY = 1000

    def flush_test(test_type):
        """Save buffered lines for a test type to a numbered CSV file."""
        if test_type not in test_lines or not test_lines[test_type]:
            return
        file_num = test_files.get(test_type, 0)
        out_path = os.path.join(out_dir, f"results_{device}_{test_type}_{file_num}.csv")
        with open(out_path, "w") as f:
            f.write(header)
            f.write("\n".join(test_lines[test_type]) + "\n")
        print(f"\n  Saved {len(test_lines[test_type])} samples to {out_path}")
        test_files[test_type] = file_num + 1
        test_lines[test_type] = []

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
                    test_type = line.split(",", 1)[0]
                    test_lines.setdefault(test_type, []).append(line)

                    if len(test_lines[test_type]) >= SAVE_EVERY:
                        flush_test(test_type)

    except KeyboardInterrupt:
        print("\nAborted by user.")
    finally:
        ser.close()

    # Flush any remaining samples
    for test_type in test_lines:
        flush_test(test_type)

    total = sum(test_files.get(t, 0) for t in test_files)
    if total > 0:
        print(f"\nDone. Saved {total} file(s) across {len(test_files)} test type(s).")
    else:
        print("\nNo benchmark results captured.")


if __name__ == "__main__":
    main()
