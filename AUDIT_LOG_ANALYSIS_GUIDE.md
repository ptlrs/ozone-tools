# Ozone Audit Log Remote Analysis Guide

## Goal
Analyze Apache Ozone Manager (OM) audit logs across 3 production servers to:
- Find failed RENAME and DELETE operations
- Identify cross-OM inconsistencies where operations succeeded on some OMs but failed on others

## Prerequisites
- Python 3.6+ with `paramiko` library (`pip install paramiko`)
- Passwordless SSH access to all 3 OM servers
- Sufficient disk space on remote OMs (~2x the audit log size for temporary files)
- Sufficient memory for processing (typically 10GB or more for large datasets)
- Network connectivity between your machine and all OM servers

## Configuration
Edit `unified_config_remote.json` before running:

```json
{
  "time_window_minutes": 1,                # Max time difference between operations
  "results_directory": "./analysis_results",
  "ssh_user": "root",                      # SSH username for all OMs
  "ssh_key_path": "/root/.ssh/id_rsa",     # SSH private key path
          
  "oms": [
    {
      "name": "OM1",
      "server": "om1.example.com",     # OM1 hostname/IP
      "log_directory": "/var/log/ozone/om/audit",
      "file_pattern": "om-audit*.log"
    },
    {
      "name": "OM2",
      "server": "om2.example.com",     # OM2 hostname/IP  
      "log_directory": "/var/log/ozone/om/audit",
      "file_pattern": "om-audit*.log"
    },
    {
      "name": "OM3",
      "server": "om3.example.com",     # OM3 hostname/IP
      "log_directory": "/var/log/ozone/om/audit",
      "file_pattern": "om-audit*.log"
    }
  ]
}
```

## Running the Analysis

```bash
./run_remote_analysis.sh
```

The script will:
1. Connect to each OM via SSH in parallel
2. Deploy and run analysis scripts on each OM
3. Collect results back to your local machine
4. Perform cross-OM consistency analysis
5. Generate output files

## Output Files

All output files are saved in the configured `results_directory`:

### 1. `inconsistent_operations.json`
Operations with different results across OMs

### 2. `analysis_summary.txt`
- Total operations analyzed
- Count of inconsistent operations  
- Processing statistics

### 3. `OM*_data.json`
Raw data from each OM

### 4. Logs
- Local: `ozone_analyzer.log` (execution log)
- Remote: `/tmp/om_analyzer_*.log` on each OM

## Monitoring Progress
```bash
# Watch local progress
tail -f ozone_analyzer.log

# Watch remote OM progress (example for OM1)
ssh om1.example.com tail -f /tmp/om_analyzer_*.log
```

## Result Analysis:
- The `CROSS-OM CONSISTENCY ANALYSIS` section of the `analysis_summary.txt` file provides a count of operations which have failed on one or more OMs
- The list of these keys is available in the `inconsistent_operations.json` file in the `operations_by_key` object
- Perform a manual validation for all such keys
