#!/usr/bin/env python3
"""
Unified Ozone Audit Analyzer with Remote Server Support

Processes audit logs from remote OM servers and automatically analyzes consistency across all OMs.
"""

import re
import os
import json
import argparse
import logging
import tempfile
import paramiko
from datetime import datetime, timedelta
from typing import Dict, List, Iterator
from collections import defaultdict
from pathlib import Path
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import sys

# Configure comprehensive logging
def setup_logging(log_file='ozone_analyzer.log'):
    """Setup logging to both file and console"""
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - [%(levelname)s] - %(name)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    console_formatter = logging.Formatter(
        '%(asctime)s - [%(levelname)s] - %(message)s'
    )
    
    # Get root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers
    logger.handlers = []
    
    # File handler with immediate flush
    class FlushFileHandler(logging.FileHandler):
        """File handler that flushes after every emit"""
        def emit(self, record):
            super().emit(record)
            self.flush()
    
    file_handler = FlushFileHandler(log_file, mode='w')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler with immediate flush
    class FlushStreamHandler(logging.StreamHandler):
        """Stream handler that flushes after every emit"""
        def emit(self, record):
            super().emit(record)
            self.flush()
    
    console_handler = FlushStreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger

# Initialize logger
logger = setup_logging()


class RemoteLogProcessor:
    """Handles processing of logs on remote servers"""
    
    def __init__(self, ssh_user: str = None, ssh_key_path: str = None):
        self.ssh_user = ssh_user or os.environ.get('USER')
        self.ssh_key_path = ssh_key_path or os.path.expanduser('~/.ssh/id_rsa')
        logger.info(f"RemoteLogProcessor initialized - User: {self.ssh_user}, Key: {self.ssh_key_path}")
        
        # Check if remote_om_analyzer.py exists
        self.remote_script_path = 'remote_om_analyzer.py'
        if not os.path.exists(self.remote_script_path):
            raise FileNotFoundError(f"Remote analyzer script not found: {self.remote_script_path}")
        logger.info(f"Remote script found: {self.remote_script_path}")
        
    def process_all_oms_parallel(self, om_configs: List[Dict], time_window_minutes: int) -> Dict[str, Dict]:
        """Process all OMs in parallel - optimized for speed"""
        logger.info(f"Starting parallel processing of {len(om_configs)} OMs with max workers")
        start_time = time.time()
        
        results = {}
        
        # Use all available CPU cores for maximum speed
        max_workers = min(len(om_configs), os.cpu_count() or 3)
        logger.info(f"Using {max_workers} parallel workers")
        
        # Use ThreadPoolExecutor for parallel SSH connections
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_om = {}
            for om_config in om_configs:
                logger.info(f"Submitting task for {om_config['name']}")
                sys.stdout.flush()
                future = executor.submit(self.process_remote_om, om_config, time_window_minutes)
                future_to_om[future] = om_config['name']
            
            # Process completed tasks
            for future in as_completed(future_to_om):
                om_name = future_to_om[future]
                try:
                    om_result = future.result()
                    results[om_name] = om_result
                    logger.info(f"✓ Completed processing {om_name} - Found {om_result['summary'].get('total_operations', 0)} operations")
                    sys.stdout.flush()
                except Exception as e:
                    logger.error(f"✗ Failed to process {om_name}: {str(e)}")
                    sys.stdout.flush()
                    results[om_name] = {'operations': [], 'summary': {}}
        
        elapsed_time = time.time() - start_time
        logger.info(f"Parallel processing completed in {elapsed_time:.2f} seconds")
        
        return results
        
    def process_remote_om(self, om_config: Dict, time_window_minutes: int) -> Dict:
        """Process logs on a remote OM server"""
        server = om_config.get('server')
        om_name = om_config['name']
        
        if not server:
            # Local processing
            logger.info(f"Processing {om_name} locally")
            return self._process_local_om(om_config, time_window_minutes)
            
        logger.info(f"Processing {om_name} on remote server: {server}")
        
        # Create SSH connection
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            logger.debug(f"Establishing SSH connection to {server}")
            ssh.connect(
                hostname=server,
                username=self.ssh_user,
                key_filename=self.ssh_key_path,
                timeout=30
            )
            logger.debug(f"SSH connection established to {server}")
            
            # Copy remote analyzer script
            sftp = ssh.open_sftp()
            try:
                remote_script_dest = f'/tmp/remote_om_analyzer_{om_name}_{int(time.time())}.py'
                logger.debug(f"Copying {self.remote_script_path} to {server}:{remote_script_dest}")
                sftp.put(self.remote_script_path, remote_script_dest)
                sftp.chmod(remote_script_dest, 0o755)
            finally:
                sftp.close()
                
            # Run analysis on remote server
            log_dir = om_config['log_directory']
            file_pattern = om_config.get('file_pattern', '*.log*')
            
            logger.info(f"Running analysis on {server} - Directory: {log_dir}, Pattern: {file_pattern}")
            sys.stdout.flush()
            
            # Get remote log file location
            remote_log_dir = '/tmp'
            
            command = f"""
            cd /tmp && \
            python3 {remote_script_dest} \
                --log-dir '{log_dir}' \
                --file-pattern '{file_pattern}' \
                --om-name '{om_name}' \
                --time-window {time_window_minutes} \
                --remote-log-dir '{remote_log_dir}'
            """
            
            logger.info(f"Remote command: {command.strip()}")
            
            stdin, stdout, stderr = ssh.exec_command(command)
            
            # Read output
            output = stdout.read().decode()
            error = stderr.read().decode()
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                logger.error(f"Remote analysis failed on {server} (exit code: {exit_status})")
                logger.error(f"Error output: {error}")
                return {'operations': [], 'summary': {}}
                
            # Parse JSON output
            try:
                summary_results = json.loads(output)
                logger.info(f"✓ Successfully received summary from {om_name}")
                logger.debug(f"Summary: {summary_results.get('summary', {})}")
                
                # Log the remote file locations
                if 'log_file' in summary_results:
                    logger.info(f"Remote log file: {summary_results['log_file']}")
                    logger.info(f"To view logs on {server}, run: ssh {self.ssh_user}@{server} 'tail -f {summary_results['log_file']}'")
                
                if 'results_file' in summary_results and summary_results['results_file']:
                    logger.info(f"Remote results file: {summary_results['results_file']}")
                    
                    # Copy results file back
                    sftp = ssh.open_sftp()
                    try:
                        local_results_file = f'/tmp/om_results_{om_name}_{int(time.time())}.json'
                        logger.debug(f"Copying results from {server}:{summary_results['results_file']} to {local_results_file}")
                        sftp.get(summary_results['results_file'], local_results_file)
                        
                        # Load the full results
                        with open(local_results_file, 'r') as f:
                            full_results = json.load(f)
                        
                        # Clean up local temp file
                        os.unlink(local_results_file)
                        
                        # Clean up remote files
                        ssh.exec_command(f"rm -f {remote_script_dest} {summary_results['results_file']}")
                        
                        # Add the log file location to results
                        full_results['log_file'] = summary_results['log_file']
                        full_results['file_map'] = summary_results.get('file_map', {}) # Store file map
                        
                        return full_results
                        
                    finally:
                        sftp.close()
                else:
                    logger.error(f"No results file received from {server}")
                    return {'operations': [], 'summary': {}}
                    
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON summary from {server}")
                logger.error(f"Raw output: {output[:500]}...")
                logger.error(f"Error output: {error}")
                return {'operations': [], 'summary': {}}
                
        except paramiko.AuthenticationException as e:
            logger.error(f"Authentication failed for {server}: {e}")
            return {'operations': [], 'summary': {}}
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for {server}: {e}")
            return {'operations': [], 'summary': {}}
        except Exception as e:
            logger.error(f"Unexpected error connecting to {server}: {e}", exc_info=True)
            return {'operations': [], 'summary': {}}
            
        finally:
            ssh.close()
            logger.debug(f"SSH connection closed for {server}")
            
    def _process_local_om(self, om_config: Dict, time_window_minutes: int) -> Dict:
        """Process logs on local filesystem"""
        logger.info(f"Processing {om_config['name']} from local filesystem")
        
        # Run the remote script locally
        cmd = [
            'python3', self.remote_script_path,
            '--log-dir', om_config['log_directory'],
            '--file-pattern', om_config.get('file_pattern', '*.log*'),
            '--om-name', om_config['name'],
            '--time-window', str(time_window_minutes)
        ]
        
        logger.debug(f"Running local command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"Local analysis failed: {result.stderr}")
            return {'operations': [], 'summary': {}}
            
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse JSON from local execution")
            logger.error(f"Output: {result.stdout[:500]}...")
            return {'operations': [], 'summary': {}}


class UnifiedRemoteOzoneAnalyzer:
    """Main analyzer that coordinates analysis across remote OMs"""
    
    def __init__(self, config_file: str):
        logger.info(f"Initializing UnifiedRemoteOzoneAnalyzer with config: {config_file}")
        
        with open(config_file, 'r') as f:
            self.config = json.load(f)
            
        self.time_window = timedelta(minutes=self.config.get('time_window_minutes', 60))
        self.results_dir = self.config.get('results_directory', './analysis_results')
        os.makedirs(self.results_dir, exist_ok=True)
        
        logger.info(f"Configuration loaded - Time window: {self.time_window.total_seconds()/60} min, Results dir: {self.results_dir}")
        
        # Remote processor
        self.remote_processor = RemoteLogProcessor(
            ssh_user=self.config.get('ssh_user'),
            ssh_key_path=self.config.get('ssh_key_path')
        )
        
    def analyze_all_oms(self):
        """Main entry point - analyzes all OMs and produces final report"""
        logger.info("="*80)
        logger.info("Starting Unified Ozone Audit Analysis")
        logger.info("="*80)
        logger.info(f"Time window: {self.time_window.total_seconds() / 60} minutes")
        logger.info(f"Number of OMs to analyze: {len(self.config['oms'])}")
        logger.info(f"Log file will be written to: ozone_analyzer.log")
        logger.info("You can tail the log file to follow progress: tail -f ozone_analyzer.log")
        logger.info("")
        logger.info("Remote logs will be created on each OM server in /tmp/")
        logger.info("You can SSH to each server and tail those logs for detailed progress")
        logger.info("")
        
        overall_start = time.time()
        
        # Step 1: Process each OM's audit logs IN PARALLEL
        logger.info("STEP 1: Processing audit logs from all OMs in parallel")
        logger.info("-"*60)
        sys.stdout.flush()
        
        om_data = self.remote_processor.process_all_oms_parallel(
            self.config['oms'],
            self.config.get('time_window_minutes', 60)
        )
        
        # Save intermediate results
        for om_name, om_results in om_data.items():
            om_file = os.path.join(self.results_dir, f"{om_name}_data.json")
            with open(om_file, 'w') as f:
                json.dump({
                    'om_name': om_name,
                    'summary': om_results.get('summary', {}),
                    'analysis_timestamp': datetime.now().isoformat(),
                    'remote_log_file': om_results.get('log_file', 'N/A')
                }, f, indent=2)
            logger.info(f"Saved {om_name} summary to {om_file}")
            
        # Step 2: Analyze cross-OM consistency
        logger.info("")
        logger.info("STEP 2: Analyzing cross-OM consistency")
        logger.info("-"*60)
        sys.stdout.flush()
        
        consistency_start = time.time()
        cross_om_results = self._analyze_cross_om_consistency(om_data)
        consistency_time = time.time() - consistency_start
        logger.info(f"Cross-OM consistency analysis completed in {consistency_time:.2f} seconds")
        
        # Step 3: Generate final report
        logger.info("")
        logger.info("STEP 3: Generating final reports")
        logger.info("-"*60)
        
        final_report = self._generate_final_report(om_data, cross_om_results)
        
        # Save reports split into multiple files
        logger.info("Saving analysis results (inconsistencies only)...")
        
        # 1. Save summary and metadata
        summary_file = os.path.join(self.results_dir, 'analysis_summary.json')
        summary_data = {
            'analysis_metadata': final_report['analysis_metadata'],
            'om_summaries': final_report['om_summaries'],
            'remote_logs': final_report['remote_logs'],
            'key_findings': final_report['key_findings'],
            'cross_om_summary': cross_om_results['summary']
        }
        with open(summary_file, 'w') as f:
            json.dump(summary_data, f, indent=2, default=str)
        logger.info(f"Saved summary to {summary_file}")
        
        # Helper function to group operations by key
        def group_by_key(operations):
            """Group operations by their key"""
            grouped = defaultdict(list)
            for op in operations:
                grouped[op['key']].append(op)
            return dict(grouped)
        
        # 2. Save inconsistent operations (all 3 OMs, different results)
        if cross_om_results['inconsistent']:
            inconsistent_file = os.path.join(self.results_dir, 'inconsistent_operations.json')
            grouped_inconsistent = group_by_key(cross_om_results['inconsistent'])
            with open(inconsistent_file, 'w') as f:
                json.dump({
                    'category': 'inconsistent',
                    'total_operations': len(cross_om_results['inconsistent']),
                    'unique_keys': len(grouped_inconsistent),
                    'operations_by_key': grouped_inconsistent
                }, f, indent=2, default=str)
            logger.info(f"Saved {len(cross_om_results['inconsistent'])} inconsistent operations ({len(grouped_inconsistent)} unique keys) to {inconsistent_file}")
            
        # 3. Save problematic insufficient operations (<3 OMs, different results)
        if cross_om_results['insufficient_problematic']:
            insufficient_file = os.path.join(self.results_dir, 'insufficient_problematic.json')
            grouped_insufficient = group_by_key(cross_om_results['insufficient_problematic'])
            with open(insufficient_file, 'w') as f:
                json.dump({
                    'category': 'insufficient_problematic',
                    'total_operations': len(cross_om_results['insufficient_problematic']),
                    'unique_keys': len(grouped_insufficient),
                    'operations_by_key': grouped_insufficient
                }, f, indent=2, default=str)
            logger.info(f"Saved {len(cross_om_results['insufficient_problematic'])} problematic insufficient operations ({len(grouped_insufficient)} unique keys) to {insufficient_file}")
            
        # Also save a human-readable summary
        summary_txt_file = os.path.join(self.results_dir, 'analysis_summary.txt')
        self._write_human_summary(final_report, summary_txt_file)
        logger.info(f"Saved summary to {summary_txt_file}")
        
        overall_time = time.time() - overall_start
        
        logger.info("")
        logger.info("="*80)
        logger.info("ANALYSIS COMPLETE (Inconsistencies Only)")
        logger.info("="*80)
        logger.info(f"Total execution time: {overall_time:.2f} seconds ({overall_time/60:.1f} minutes)")
        logger.info(f"Results saved to: {self.results_dir}")
        logger.info("")
        logger.info("Output files:")
        logger.info(f"  - {summary_file} (Summary and metadata)")
        if cross_om_results['inconsistent']:
            logger.info(f"  - inconsistent_operations.json ({cross_om_results['summary']['inconsistent_count']} operations)")
        if cross_om_results['insufficient_problematic']:
            logger.info(f"  - insufficient_problematic.json ({cross_om_results['summary']['insufficient_problematic_count']} operations)")
        logger.info(f"  - {summary_txt_file}")
        logger.info("")
        logger.info("Performance:")
        logger.info(f"  - Skipped {cross_om_results['summary']['skipped_consistent']} consistent operations")
        logger.info(f"  - Skipped {cross_om_results['summary']['skipped_insufficient_same']} insufficient with same results")
        logger.info("")
        logger.info("Log files:")
        logger.info(f"  - ozone_analyzer.log (Local)")
        for om_name, om_results in om_data.items():
            if 'log_file' in om_results:
                logger.info(f"  - {om_name}: {om_results['log_file']}")
        logger.info("="*80)
        
        # Print key findings
        self._print_key_findings(final_report)
        
    def _analyze_cross_om_consistency(self, om_data: Dict) -> Dict:
        """Analyze operations consistency across OMs - optimized for inconsistencies only"""
        logger.info("Analyzing for inconsistencies only (skipping consistent operations)")
        sys.stdout.flush()
        
        # Create file maps for source verification
        file_maps = {}
        for om_name, data in om_data.items():
            ops_count = len(data.get('operations', []))
            logger.info(f"Received {ops_count} operations from {om_name}")
            if 'file_map' in data:
                file_maps[om_name] = data['file_map']
        
        # Process operations - only keep what we need
        operations_by_key = defaultdict(list)
        total_operations = 0
        operation_id = 0
        
        for om_name, data in om_data.items():
            om_ops = len(data.get('operations', []))
            total_operations += om_ops
            logger.debug(f"Processing {om_ops} operations from {om_name}")
            
            for op in data.get('operations', []):
                operation_id += 1
                operations_by_key[op['key']].append({
                    'id': operation_id,
                    'om': om_name,
                    'op': op['operation'],
                    'res': op['result'],
                    'ts': op['timestamp'],
                    'src': op.get('src', 'unknown')
                })
            
            # Clear the original data immediately
            data['operations'] = []
                
        logger.info(f"Total operations to analyze: {total_operations}")
        logger.info(f"Unique keys to analyze: {len(operations_by_key)}")
        sys.stdout.flush()
        
        # Store file maps for later reference
        self.file_maps = file_maps
        
        # Analyze only for inconsistencies
        analysis = {
            'total_keys': len(operations_by_key),
            'inconsistent': [],
            'insufficient_problematic': [],  # Only insufficient with different results
            'summary': {
                'inconsistent_count': 0,
                'insufficient_problematic_count': 0,
                'skipped_consistent': 0,
                'skipped_insufficient_same': 0,
                'oms_in_inconsistent': set(),  # Track OMs that appear in inconsistent operations
                'oms_with_failures': set(),    # Track OMs that have FAILURE in inconsistent operations
                'oms_without_failures': set()  # Track OMs that never have FAILURE in inconsistent operations
            }
        }
        
        logger.info("Analyzing for inconsistencies")
        sys.stdout.flush()
        analyzed_keys = 0
        last_log_time = time.time()
        
        # Process keys - early filtering
        for key, operations in operations_by_key.items():
            # More frequent updates - every 1000 keys or every 5 seconds
            if analyzed_keys % 1000 == 0 or (time.time() - last_log_time) > 5:
                progress_pct = (analyzed_keys / len(operations_by_key) * 100) if len(operations_by_key) > 0 else 0
                logger.info(f"Analyzed {analyzed_keys:,}/{len(operations_by_key):,} keys ({progress_pct:.1f}%)")
                sys.stdout.flush()
                last_log_time = time.time()
            
            # Quick check - if all operations have same result, skip
            unique_results = set(op['res'] for op in operations)
            if len(unique_results) == 1:
                analysis['summary']['skipped_consistent'] += 1
                analyzed_keys += 1
                continue
            
            # Group operations for this key
            groups = self._group_operations_inconsistent_only(operations, key)
            for group in groups:
                result = self._analyze_group_inconsistent_only(key, group, analysis)
                if result == 'skipped':
                    analysis['summary']['skipped_consistent'] += 1
                elif result == 'skipped_insufficient':
                    analysis['summary']['skipped_insufficient_same'] += 1
                
            analyzed_keys += 1
            
            # Clear processed operations immediately
            operations.clear()
                
        # Update counts
        analysis['summary']['inconsistent_count'] = len(analysis['inconsistent'])
        analysis['summary']['insufficient_problematic_count'] = len(analysis['insufficient_problematic'])
        
        # Calculate OMs without failures in inconsistent operations
        analysis['summary']['oms_without_failures'] = analysis['summary']['oms_in_inconsistent'] - analysis['summary']['oms_with_failures']
        
        logger.info(f"Analyzed {analyzed_keys:,}/{len(operations_by_key):,} keys (100.0%)")
        sys.stdout.flush()
        
        logger.info(f"Analysis complete (inconsistencies only):")
        logger.info(f"  - INCONSISTENT (3 OMs, different results): {analysis['summary']['inconsistent_count']}")
        logger.info(f"  - PROBLEMATIC INSUFFICIENT (<3 OMs, different results): {analysis['summary']['insufficient_problematic_count']}")
        logger.info(f"  - Skipped consistent operations: {analysis['summary']['skipped_consistent']}")
        logger.info(f"  - Skipped insufficient with same results: {analysis['summary']['skipped_insufficient_same']}")
        sys.stdout.flush()
            
        return analysis
        
    def _group_operations_inconsistent_only(self, operations: List[Dict], key: str) -> List[Dict]:
        """Group operations - optimized for finding inconsistencies only"""
        operations = sorted(operations, key=lambda x: x['ts'])
        used_ids = set()
        groups = []
        
        i = 0
        while i < len(operations):
            if operations[i]['id'] in used_ids:
                i += 1
                continue
                
            # Start a new group
            group = {
                'op': operations[i]['op'],
                'ops': [operations[i]],
                'oms': {operations[i]['om']},
                'results': {operations[i]['res']}  # Track unique results
            }
            used_ids.add(operations[i]['id'])
            
            # If first operation is part of larger group, find matches
            base_ts = operations[i]['ts']
            base_time = datetime.strptime(base_ts, "%Y-%m-%d %H:%M:%S,%f")
            j = i + 1
            
            while j < len(operations) and len(group['oms']) < 3:
                if operations[j]['id'] in used_ids:
                    j += 1
                    continue
                    
                op_time = datetime.strptime(operations[j]['ts'], "%Y-%m-%d %H:%M:%S,%f")
                time_diff = (op_time - base_time).total_seconds()
                
                if (operations[j]['op'] == group['op'] and
                    operations[j]['om'] not in group['oms'] and
                    0 <= time_diff <= self.time_window.total_seconds()):
                    
                    group['ops'].append(operations[j])
                    group['oms'].add(operations[j]['om'])
                    group['results'].add(operations[j]['res'])
                    used_ids.add(operations[j]['id'])
                    
                j += 1
            
            # Only keep groups that might be inconsistent
            if len(group['results']) > 1 or len(group['oms']) < 3:
                groups.append(group)
                
            i += 1
            
        return groups
        
    def _analyze_group_inconsistent_only(self, key: str, group: Dict, analysis: Dict) -> str:
        """Analyze a group - only process inconsistent cases"""
        om_results = {}
        timestamps = {}
        sources = {}
        
        for op in group['ops']:
            om = op['om']
            om_results[om] = op['res']
            timestamps[om] = op['ts']
            sources[om] = op.get('src', 'unknown')
                
        unique_results = set(om_results.values())
        om_count = len(om_results)
        
        # Skip if all results are the same (consistent)
        if len(unique_results) == 1:
            if om_count < 3:
                # Insufficient with same results - not interested
                return 'skipped_insufficient'
            else:
                # Consistent success or failure - not interested
                return 'skipped'
        
        # We have different results - this is what we want
        group_info = {
            'key': key,
            'operation': group['op'],
            'om_count': om_count,
            'om_results': om_results,
            'timestamps': timestamps,
            'sources': sources
        }
        
        if om_count < 3:
            # Insufficient with different results - interested
            group_info['missing_oms'] = [om for om in ['OM1', 'OM2', 'OM3'] if om not in om_results]
            success_oms = [om for om, r in om_results.items() if r == 'SUCCESS']
            failure_oms = [om for om, r in om_results.items() if r == 'FAILURE']
            group_info['issue'] = f"Insufficient data with conflict: Succeeded on {success_oms} but failed on {failure_oms}"
            analysis['insufficient_problematic'].append(group_info)
        else:
            # All 3 OMs but different results - inconsistent
            success_oms = [om for om, r in om_results.items() if r == 'SUCCESS']
            failure_oms = [om for om, r in om_results.items() if r == 'FAILURE']
            group_info['issue'] = f"Succeeded on {success_oms} but failed on {failure_oms}"
            analysis['inconsistent'].append(group_info)
            
            # Track OMs in inconsistent operations
            for om, result in om_results.items():
                analysis['summary']['oms_in_inconsistent'].add(om)
                if result == 'FAILURE':
                    analysis['summary']['oms_with_failures'].add(om)
            
        return 'processed'
        
    def _generate_final_report(self, om_data: Dict, cross_om_results: Dict) -> Dict:
        """Generate comprehensive final report"""
        logger.info("Generating final report with key findings")
        
        return {
            'analysis_metadata': {
                'timestamp': datetime.now().isoformat(),
                'config_file': self.config.get('config_file', 'unknown'),
                'time_window_minutes': self.time_window.total_seconds() / 60,
                'oms_analyzed': list(om_data.keys())
            },
            'om_summaries': {
                om: data.get('summary', {}) for om, data in om_data.items()
            },
            'remote_logs': {
                om: data.get('log_file', 'N/A') for om, data in om_data.items()
            },
            'cross_om_analysis': cross_om_results,
            'key_findings': self._extract_key_findings(om_data, cross_om_results)
        }
        
    def _extract_key_findings(self, om_data: Dict, cross_om_results: Dict) -> Dict:
        """Extract the most important findings"""
        findings = {
            'critical_issues': [],
            'warnings': [],
            'summary': {}
        }
        
        if cross_om_results['summary']['inconsistent_count'] > 0:
            findings['critical_issues'].append({
                'type': 'INCONSISTENT_OPERATIONS',
                'count': cross_om_results['summary']['inconsistent_count'],
                'message': f"Found {cross_om_results['summary']['inconsistent_count']} operations with inconsistent results across OMs",
                'examples': cross_om_results['inconsistent'][:5]
            })
            
        om_totals = {om: data.get('summary', {}).get('total_operations', 0) for om, data in om_data.items()}
        max_ops = max(om_totals.values()) if om_totals else 0
        min_ops = min(om_totals.values()) if om_totals else 0
        
        if max_ops > 0 and min_ops < max_ops * 0.1:
            findings['warnings'].append({
                'type': 'OM_IMBALANCE',
                'message': f"Significant operation count imbalance: {om_totals}",
                'details': om_totals
            })
            
        findings['summary'] = {
            'total_unique_keys': cross_om_results['total_keys'],
            'problematic_keys': cross_om_results['summary']['inconsistent_count'],
            'operations_per_om': om_totals
        }
        
        return findings
        
    def _write_human_summary(self, report: Dict, filepath: str):
        with open(filepath, 'w') as f:
            f.write("OZONE AUDIT ANALYSIS SUMMARY (INCONSISTENCIES ONLY)\n")
            f.write("=" * 80 + "\n")
            f.write(f"Analysis Date: {report['analysis_metadata']['timestamp']}\n")
            f.write(f"Time Window: {report['analysis_metadata']['time_window_minutes']} minutes\n")
            f.write(f"OMs Analyzed: {', '.join(report['analysis_metadata']['oms_analyzed'])}\n")
            f.write("\n")
            
            f.write("OM OPERATION SUMMARY\n")
            f.write("-" * 40 + "\n")
            for om, summary in report['om_summaries'].items():
                f.write(f"\n{om}:\n")
                f.write(f"  Total Operations: {summary.get('total_operations', 0):,}\n")
                f.write(f"  Successful: {summary.get('successful', 0):,}\n")
                f.write(f"  Failed: {summary.get('failed', 0):,}\n")

                
            f.write("\n\nCROSS-OM INCONSISTENCY ANALYSIS\n")
            f.write("-" * 40 + "\n")
            cross_summary = report['cross_om_analysis']['summary']
            f.write(f"Total Unique Keys: {report['cross_om_analysis']['total_keys']:,}\n")
            f.write(f"INCONSISTENT (All 3 OMs, different results): {cross_summary['inconsistent_count']:,}\n")
            f.write(f"PROBLEMATIC INSUFFICIENT (<3 OMs, different results): {cross_summary['insufficient_problematic_count']:,}\n")
            f.write(f"Skipped Consistent Operations: {cross_summary['skipped_consistent']:,}\n")
            f.write(f"Skipped Insufficient (same results): {cross_summary['skipped_insufficient_same']:,}\n")
            
            f.write("\n\nKEY FINDINGS\n")
            f.write("-" * 40 + "\n")
            
            if report['key_findings']['critical_issues']:
                f.write("\nCRITICAL ISSUES:\n")
                for issue in report['key_findings']['critical_issues']:
                    f.write(f"  - {issue['message']}\n")
                    
            if report['key_findings']['warnings']:
                f.write("\nWARNINGS:\n")
                for warning in report['key_findings']['warnings']:
                    f.write(f"  - {warning['message']}\n")
                    
            if cross_summary['inconsistent_count'] > 0:
                f.write("\n\nEXAMPLES OF INCONSISTENT OPERATIONS:\n")
                f.write("-" * 40 + "\n")
                for i, case in enumerate(report['cross_om_analysis']['inconsistent'][:10], 1):
                    f.write(f"\n{i}. Key: {case['key']}\n")
                    f.write(f"   Operation: {case['operation']}\n")
                    f.write(f"   Results: {case['om_results']}\n")
                    f.write(f"   Issue: {case.get('issue', 'N/A')}\n")
                    
            if cross_summary['insufficient_problematic_count'] > 0:
                f.write("\n\nEXAMPLES OF PROBLEMATIC INSUFFICIENT OPERATIONS:\n")
                f.write("-" * 40 + "\n")
                for i, case in enumerate(report['cross_om_analysis']['insufficient_problematic'][:10], 1):
                    f.write(f"\n{i}. Key: {case['key']}\n")
                    f.write(f"   Operation: {case['operation']}\n")
                    f.write(f"   Results: {case['om_results']}\n")
                    f.write(f"   Missing OMs: {case.get('missing_oms', [])}\n")
                    f.write(f"   Issue: {case.get('issue', 'N/A')}\n")
                    
            # Write OMs without failures
            oms_without_failures = cross_summary.get('oms_without_failures', set())
            f.write("\n\nOMs WITHOUT FAILURES IN INCONSISTENT OPERATIONS:\n")
            f.write("-" * 40 + "\n")
            if oms_without_failures:
                f.write("The following OMs have NOT faced any FAILURE among the detected inconsistent operations:\n")
                for om in sorted(oms_without_failures):
                    f.write(f"  - {om}\n")
                f.write(f"\nTotal: {len(oms_without_failures)} OM(s) only had SUCCESS results in inconsistent operations.\n")
            else:
                f.write("All OMs involved in inconsistent operations have experienced at least one FAILURE.\n")
                    
    def _print_key_findings(self, report: Dict):
        """Print key findings to console"""
        print("\n" + "=" * 80)
        print("KEY FINDINGS (INCONSISTENCIES ONLY)")
        print("=" * 80)
        
        cross_summary = report['cross_om_analysis']['summary']
        
        print(f"\nTotal Unique Keys: {report['cross_om_analysis']['total_keys']:,}")
        print(f"INCONSISTENT Cases (All 3 OMs): {cross_summary['inconsistent_count']:,}")
        print(f"PROBLEMATIC INSUFFICIENT Cases: {cross_summary['insufficient_problematic_count']:,}")
        print(f"Skipped Consistent Operations: {cross_summary['skipped_consistent']:,}")
        
        if cross_summary['inconsistent_count'] > 0:
            print(f"\n⚠️  CRITICAL: Found {cross_summary['inconsistent_count']} operations with inconsistent results!")
            print("These operations succeeded on some OMs but failed on others.")
            print(f"See {os.path.join(self.results_dir, 'inconsistent_operations.json')} for details.")
            
        if cross_summary['insufficient_problematic_count'] > 0:
            print(f"\n⚠️  WARNING: Found {cross_summary['insufficient_problematic_count']} problematic insufficient operations!")
            print("These operations are missing from some OMs and have conflicting results.")
            print(f"See {os.path.join(self.results_dir, 'insufficient_problematic.json')} for details.")
            
        # Print OMs without failures in inconsistent operations
        oms_without_failures = cross_summary.get('oms_without_failures', set())
        if oms_without_failures:
            print(f"\n✅ OMs that have NOT faced any FAILURE in inconsistent operations:")
            for om in sorted(oms_without_failures):
                print(f"   - {om}")
            print(f"\nThese {len(oms_without_failures)} OM(s) only had SUCCESS results among the detected inconsistent operations.")
        else:
            print(f"\n❌ All OMs involved in inconsistent operations have experienced at least one FAILURE.")
            
        print(f"\nDetailed logs available in: ozone_analyzer.log")
        print("\nAnalysis results:")
        print(f"  - analysis_summary.json - Overview and metadata")
        print(f"  - inconsistent_operations.json - Operations with different results across all 3 OMs")
        print(f"  - insufficient_problematic.json - Operations with conflicts when <3 OMs have data")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Unified Ozone Audit Analyzer with remote server support'
    )
    parser.add_argument(
        '--config',
        type=str,
        required=True,
        help='Path to configuration file'
    )
    
    args = parser.parse_args()
    
    logger.info(f"Starting Ozone Analyzer with config file: {args.config}")
    
    # Create and run analyzer
    analyzer = UnifiedRemoteOzoneAnalyzer(args.config)
    analyzer.analyze_all_oms()


if __name__ == '__main__':
    main()
