#!/usr/bin/env python3
"""
Remote OM Analyzer Script
Runs on individual OM servers to process audit logs with detailed progress tracking
"""

import re
import glob
import os
import json
import argparse
from collections import defaultdict
import sys
import time
import logging
from datetime import datetime
import signal

# Global flag for graceful shutdown
shutdown_requested = False

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global shutdown_requested
    shutdown_requested = True
    logging.info("Shutdown signal received, finishing current operation...")

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def setup_logging(om_name, log_dir="/tmp"):
    """Setup comprehensive logging for remote execution"""
    log_file = os.path.join(log_dir, f"om_analyzer_{om_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    # Create formatters
    formatter = logging.Formatter(
        '%(asctime)s - [%(levelname)s] - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # File handler with immediate flush
    class FlushFileHandler(logging.FileHandler):
        """File handler that flushes after every emit"""
        def emit(self, record):
            super().emit(record)
            self.flush()
    
    file_handler = FlushFileHandler(log_file, mode='w')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Also log to stderr for remote capture (with flush)
    class FlushStreamHandler(logging.StreamHandler):
        """Stream handler that flushes after every emit"""
        def emit(self, record):
            super().emit(record)
            self.flush()
    
    stderr_handler = FlushStreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.INFO)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)
    
    logging.info(f"Remote OM analyzer started for {om_name}")
    logging.info(f"Log file: {log_file}")
    logging.info(f"PID: {os.getpid()}")
    
    return log_file

# Regex patterns
AUDIT_LINE_PATTERN = re.compile(
    rb'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})'
    rb'.*?op=(?P<operation>\w+)'
    rb'.*?{(?P<params>[^}]+)}'
    rb'.*?ret=(?P<result>\w+)'
)

KEY_PATTERNS = {
    'RENAME_KEY': re.compile(rb'srcKey=([^,}]+)'),
    'DELETE_KEY': re.compile(rb'key=([^,}]+)')
}

class ProgressTracker:
    """Track and report processing progress"""
    def __init__(self, total_files):
        self.total_files = total_files
        self.current_file = 0
        self.current_file_name = ""
        self.lines_processed = 0
        self.operations_found = 0
        self.start_time = time.time()
        self.file_start_time = None
        
    def start_file(self, filename, file_size):
        self.current_file += 1
        self.current_file_name = filename
        self.file_start_time = time.time()
        self.lines_processed = 0
        
        size_gb = file_size / (1024 ** 3)
        logging.info(f"Processing file {self.current_file}/{self.total_files}: {filename} ({size_gb:.2f} GB)")
        
    def update_progress(self, lines, operations):
        self.lines_processed = lines
        self.operations_found = operations
        
        # Log progress every million lines
        if lines % 1000000 == 0 and lines > 0:
            elapsed = time.time() - self.file_start_time
            rate = lines / elapsed if elapsed > 0 else 0
            logging.info(f"  Progress: {lines:,} lines processed ({rate:,.0f} lines/sec) - {operations} operations found")
            
    def finish_file(self, total_operations):
        elapsed = time.time() - self.file_start_time
        logging.info(f"  Completed {self.current_file_name} in {elapsed:.1f} seconds - Found {total_operations:,} operations")
        
    def get_summary(self):
        total_elapsed = time.time() - self.start_time
        return {
            'files_processed': self.current_file,
            'total_time_seconds': total_elapsed,
            'operations_found': self.operations_found
        }

def process_file_in_chunks(filepath, progress_tracker, chunk_size=1024*1024*100):  # 100MB chunks for speed
    """Process a file in chunks - optimized for speed with more memory"""
    operations = []
    operation_buffer = []
    chunk_num = 0
    temp_files = []
    
    # Use file index for compact source tracking
    file_index = progress_tracker.current_file
    
    try:
        file_size = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        progress_tracker.start_file(filename, file_size)
        
        line_count = 0
        partial_line = b''
        
        with open(filepath, 'rb') as f:
            while not shutdown_requested:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                    
                # Handle partial lines
                chunk = partial_line + chunk
                lines = chunk.split(b'\n')
                
                # Save the last partial line for next iteration
                if chunk[-1] != b'\n':
                    partial_line = lines[-1]
                    lines = lines[:-1]
                else:
                    partial_line = b''
                
                # Process lines in this chunk
                for line in lines:
                    if shutdown_requested:
                        break
                        
                    line_count += 1
                    
                    # Less frequent progress updates for speed
                    if line_count % 1000000 == 0:
                        progress_tracker.update_progress(line_count, len(operation_buffer))
                    
                    match = AUDIT_LINE_PATTERN.search(line)
                    if not match:
                        continue
                        
                    data = match.groupdict()
                    operation = data['operation'].decode('utf-8', errors='ignore')
                    
                    if operation not in ['RENAME_KEY', 'DELETE_KEY']:
                        continue
                        
                    result = data['result'].decode('utf-8', errors='ignore')
                    timestamp = data['timestamp'].decode('utf-8', errors='ignore')
                    params = data['params']
                    
                    # Extract key
                    key = None
                    if operation == 'RENAME_KEY':
                        match = KEY_PATTERNS['RENAME_KEY'].search(params)
                        if match:
                            key = match.group(1).decode('utf-8', errors='ignore').strip()
                    elif operation == 'DELETE_KEY':
                        match = KEY_PATTERNS['DELETE_KEY'].search(params)
                        if match:
                            key = match.group(1).decode('utf-8', errors='ignore').strip()
                            
                    if key:
                        operation_buffer.append({
                            'timestamp': timestamp,
                            'operation': operation,
                            'result': result,
                            'key': key,
                            'src': f"{file_index}:{line_count}"
                        })
                        
                        # Larger buffer for speed (500k operations)
                        if len(operation_buffer) >= 500000:
                            chunk_file = f"/tmp/chunk_{os.getpid()}_{chunk_num}.json"
                            with open(chunk_file, 'w') as cf:
                                json.dump(operation_buffer, cf)
                            temp_files.append(chunk_file)
                            chunk_num += 1
                            operation_buffer = []
                            logging.info(f"  Wrote chunk {chunk_num} with 500k operations")
                        
        if shutdown_requested:
            logging.warning(f"File processing interrupted: {filename}")
        else:
            # Write any remaining operations
            if operation_buffer:
                chunk_file = f"/tmp/chunk_{os.getpid()}_{chunk_num}.json"
                with open(chunk_file, 'w') as cf:
                    json.dump(operation_buffer, cf)
                temp_files.append(chunk_file)
                logging.info(f"  Wrote final chunk with {len(operation_buffer)} operations")
            
            total_ops = chunk_num * 500000 + len(operation_buffer) if temp_files else 0
            
            progress_tracker.finish_file(total_ops)
            
            # Return temp files info
            return temp_files
                    
    except Exception as e:
        logging.error(f"Error processing {filepath}: {e}", exc_info=True)
        # Clean up temp files on error
        for tf in temp_files:
            if os.path.exists(tf):
                os.unlink(tf)
        
    return []

def analyze_operations(operations):
    """Analyze operations and create summary statistics"""
    logging.info("Analyzing operations...")
    
    summary = {
        'total_operations': len(operations),
        'successful': 0,
        'failed': 0,
        'by_operation': defaultdict(lambda: {'SUCCESS': 0, 'FAILURE': 0}),
        'unique_keys_count': {
            'all': 0,
            'successful': 0,
            'failed': 0
        }
    }
    
    unique_keys = {
        'all': set(),
        'successful': set(),
        'failed': set()
    }
    
    for op in operations:
        result = op['result']
        operation = op['operation']
        key = op['key']
        
        if result == 'SUCCESS':
            summary['successful'] += 1
            unique_keys['successful'].add(key)
        else:
            summary['failed'] += 1
            unique_keys['failed'].add(key)
            
        unique_keys['all'].add(key)
        summary['by_operation'][operation][result] += 1
        
    summary['unique_keys_count'] = {
        k: len(v) for k, v in unique_keys.items()
    }
    
    # Convert defaultdict to regular dict for JSON
    summary['by_operation'] = dict(summary['by_operation'])
    
    logging.info(f"Analysis complete: {summary['successful']:,} successful, {summary['failed']:,} failed operations")
    logging.info(f"Unique keys: {summary['unique_keys_count']['all']:,} total, "
                 f"{summary['unique_keys_count']['failed']:,} failed")
    
    return summary

def main():
    parser = argparse.ArgumentParser(description='Process OM audit logs on remote server')
    parser.add_argument('--log-dir', required=True, help='Directory containing audit logs')
    parser.add_argument('--file-pattern', default='*.log*', help='File pattern to match')
    parser.add_argument('--om-name', required=True, help='Name of this OM')
    parser.add_argument('--time-window', type=int, default=60, help='Time window in minutes')
    parser.add_argument('--remote-log-dir', default='/tmp', help='Directory for remote log file')
    
    args = parser.parse_args()
    
    # Setup logging
    log_file = setup_logging(args.om_name, args.remote_log_dir)
    
    try:
        # Log configuration
        logging.info("Configuration:")
        logging.info(f"  OM Name: {args.om_name}")
        logging.info(f"  Log Directory: {args.log_dir}")
        logging.info(f"  File Pattern: {args.file_pattern}")
        logging.info(f"  Time Window: {args.time_window} minutes")
        
        # Find all log files
        pattern = os.path.join(args.log_dir, args.file_pattern)
        log_files = sorted(glob.glob(pattern))
        
        if not log_files:
            logging.error(f"No files found matching: {pattern}")
            print(json.dumps({'operations': [], 'summary': {}, 'log_file': log_file}))
            sys.exit(0)
            
        logging.info(f"Found {len(log_files)} log files to process")
        for f in log_files:
            size_mb = os.path.getsize(f) / (1024 * 1024)
            logging.info(f"  - {os.path.basename(f)} ({size_mb:.1f} MB)")
        
        # Initialize progress tracker
        progress = ProgressTracker(len(log_files))
        
        # Create file map for source verification
        file_map = {}
        for i, log_file in enumerate(log_files):
            file_map[str(i)] = os.path.basename(log_file)
        logging.info(f"File map created: {file_map}")
        
        # Process all files
        all_operations = []
        
        for log_file in log_files:
            if shutdown_requested:
                logging.warning("Shutdown requested, stopping file processing")
                break
                
            temp_files = process_file_in_chunks(log_file, progress)
            # Read operations from temp files and merge
            for tf in temp_files:
                if os.path.exists(tf):
                    with open(tf, 'r') as f:
                        chunk_operations = json.load(f)
                        all_operations.extend(chunk_operations)
                    os.unlink(tf)  # Clean up temp file after reading
            progress.operations_found = len(all_operations)
            
        # Get final summary
        process_summary = progress.get_summary()
        logging.info(f"Processing complete: {process_summary['files_processed']} files in "
                     f"{process_summary['total_time_seconds']:.1f} seconds")
        
        # Log sample operations with source info for verification
        if all_operations:
            logging.info("Sample operations with source tracking:")
            for i, op in enumerate(all_operations[:3]):
                src_parts = op.get('src', 'unknown').split(':')
                if len(src_parts) == 2:
                    file_idx, line_num = src_parts
                    file_name = file_map.get(file_idx, 'unknown')
                    logging.info(f"  {op['operation']} {op['key']} from {file_name}:{line_num}")
        
        # Analyze operations
        summary = analyze_operations(all_operations)
        
        # Prepare output
        results = {
            'operations': all_operations,
            'summary': summary,
            'log_file': log_file,
            'processing_stats': process_summary,
            'file_map': file_map  # Include file map for verification
        }
        
        # Write results to file instead of stdout (more efficient for large data)
        results_file = os.path.join(args.remote_log_dir, f"om_results_{args.om_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        logging.info(f"Writing results to file: {results_file}")
        
        with open(results_file, 'w') as f:
            json.dump(results, f)
        
        logging.info(f"Results written successfully: {os.path.getsize(results_file) / (1024 * 1024):.2f} MB")
        
        # Output only summary and file location to stdout (small JSON)
        output_summary = {
            'summary': summary,
            'log_file': log_file,
            'results_file': results_file,
            'processing_stats': process_summary,
            'status': 'success'
        }
        
        print(json.dumps(output_summary))
        
        logging.info("Remote analysis completed successfully")
        logging.info(f"To view this log on the remote server: tail -f {log_file}")
        logging.info(f"Results saved to: {results_file}")
        
    except Exception as e:
        logging.error(f"Fatal error in remote analyzer: {e}", exc_info=True)
        
        # Create a minimal error response
        print(json.dumps({
            'summary': {}, 
            'log_file': log_file,
            'results_file': None,
            'error': str(e),
            'status': 'error'
        }))
        sys.exit(1)

if __name__ == '__main__':
    main() 