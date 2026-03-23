import pandas as pd
import glob
import os

def load_safe_csv(filepath):
    parsed_data = []
    with open(filepath, "r", encoding="utf-8") as f:
        # Read and ignore the header line
        f.readline() 
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split(",", 3) 
            
            if len(parts) == 4:
                parsed_data.append(parts)
                
    # Rebuild the DataFrame and convert numbers so the math works later
    df = pd.DataFrame(parsed_data, columns=['TestType', 'Iteration', 'Elapsed_ms', 'Result'])
    df['Iteration'] = pd.to_numeric(df['Iteration'], errors='coerce')
    df['Elapsed_ms'] = pd.to_numeric(df['Elapsed_ms'], errors='coerce')
    return df

def collate_all_results():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    compiled_csv_path = os.path.join(base_dir, "compiled_results.csv")

    if os.path.exists(compiled_csv_path):
        print(f"Loading existing compiled dataset from {compiled_csv_path}...")
        master_df = pd.read_csv(compiled_csv_path)
    
    else:
        files = glob.glob(os.path.join(base_dir, "results_*.csv"))
        
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
            df = load_safe_csv(file)
            
            # Add a 'Device' column for board
            df['Device'] = device_name
            all_data.append(df)

        # 2. Combine all files into one big "Master Table"
        master_df = pd.concat(all_data, ignore_index=True)
        master_df.to_csv(compiled_csv_path, index=False)
        print(f"Compiled raw data successfully saved to: {compiled_csv_path}\n")
    
    master_df['Is_Success'] = master_df['Result'].astype(str).str.startswith('SUCCESS')

    # 3. COLLATE: Group by Device AND TestType
    summary = master_df.groupby(['Device', 'TestType']).agg(
        Avg_ms=('Elapsed_ms', 'mean'),
        Min_ms=('Elapsed_ms', 'min'),
        Max_ms=('Elapsed_ms', 'max'),
        Samples=('Elapsed_ms', 'count'),
        Success_Rate=('Is_Success', 'mean') # This gives a decimal like 0.98
    )
    
    # Format for better reading 
    summary['Success (%)'] = summary['Success_Rate'] * 100
    summary['Fail (%)'] = 100 - summary['Success (%)']
    summary = summary.drop(columns=['Success_Rate'])
    summary.columns = ['Avg (ms)', 'Min (ms)', 'Max (ms)', 'Samples', 'Success (%)', 'Fail (%)']
    summary = summary[['Avg (ms)', 'Min (ms)', 'Max (ms)', 'Success (%)', 'Fail (%)', 'Samples']]
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