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
        device_name = file.replace("results_", "").replace(".csv", "").upper()
        
        # Load the CSV
        df = pd.read_csv(file)
        
        # Add a 'Device' column for board
        df['Device'] = device_name
        all_data.append(df)

    # 2. Combine all files into one big "Master Table"
    master_df = pd.concat(all_data, ignore_index=True)

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