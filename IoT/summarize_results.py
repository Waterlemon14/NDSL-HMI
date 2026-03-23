import pandas as pd
import glob
import os

def collate_all_results():
    files = glob.glob("results_*.csv")
    
    if not files:
        print("No results files found.")
        return

    all_data = []

    for file in files:
        # Extract device name from filename (e.g., 'esp32' from 'results_esp32.csv')
        basename = os.path.basename(file)
        parts = basename.split("_")
        
        if len(parts) >= 2:
            device_name = parts[1].upper() # Grabs 'PICO', 'ESP32', etc.
        else:
            device_name = "UNKNOWN"
        
        # Load the CSV
        df = pd.read_csv(file)
        
        # Add a 'Device' column for board
        df['Device'] = device_name
        all_data.append(df)

    # 2. Combine all files into one big "Master Table"
    master_df = pd.concat(all_data, ignore_index=True)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    compiled_csv_path = os.path.join(base_dir, "compiled_results.csv")
    master_df.to_csv(compiled_csv_path, index=False)
    print(f"Compiled raw data successfully saved to: {compiled_csv_path}\n")

    # 3. COLLATE: Group by Device AND TestType
    summary = master_df.groupby(['Device', 'TestType'])['Elapsed_ms'].agg(['mean', 'min', 'max', 'count'])
    
    # Format for better reading 
    summary.columns = ['Avg (ms)', 'Min (ms)', 'Max (ms)', 'Samples']
    summary = summary.round(2)

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"final_benchmark_report.txt")
    with open(out_path, "w") as f:
        f.write("==================================================\n")
        f.write("          MULTI-DEVICE BENCHMARK REPORT           \n")
        f.write("==================================================\n\n")
        f.write(summary.to_string())
        f.write("\n\n" + "="*50 + "\n")
        f.write(f"Report Generated: {pd.Timestamp.now()}\n")
    
    print("\n" + "="*50)
    print("      MULTI-DEVICE BENCHMARK SUMMARY")
    print("="*50)
    print(summary)
    print("="*50 + "\n")
    print(f"Report saved at {out_path}\n")

if __name__ == "__main__":
    collate_all_results()