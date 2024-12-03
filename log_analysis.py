import csv
from collections import defaultdict

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def count_requests_per_ip(logs):
    ip_count = defaultdict(int)
    for log in logs:
        parts = log.split()
        ip_address = parts[0]
        ip_count[ip_address] += 1
    return ip_count

def identify_most_accessed_endpoint(logs):
    endpoint_count = defaultdict(int)
    for log in logs:
        parts = log.split()
        endpoint = parts[6]  # The endpoint is the 7th part in the log
        endpoint_count[endpoint] += 1
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1])
    return most_accessed

def detect_suspicious_activity(logs, threshold=10):
    failed_login_count = defaultdict(int)
    for log in logs:
        if '401' in log or 'Invalid credentials' in log:
            parts = log.split()
            ip_address = parts[0]
            failed_login_count[ip_address] += 1
    suspicious_ips = {ip: count for ip, count in failed_login_count.items() if count > threshold}
    return suspicious_ips

def save_results_to_csv(ip_counts, most_accessed, suspicious_activity):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Request Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for ip, count in ip_counts.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})
        
        writer.writerow({})  # Empty row for separation
        writer.writerow({'IP Address': 'Most Accessed Endpoint', 'Request Count': most_accessed[0]})
        writer.writerow({'IP Address': 'Access Count', 'Request Count': most_accessed[1]})
        
        writer.writerow({})  # Empty row for separation
        writer.writerow({'IP Address': 'Suspicious Activity', 'Request Count': 'Failed Login Attempts'})
        for ip, count in suspicious_activity.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})

def main():
    log_file_path = 'sample.log'  # Path to the log file
    logs = parse_log_file(log_file_path)

    # Count requests per IP address
    ip_counts = count_requests_per_ip(logs)
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    # Identify the most frequently accessed endpoint
    most_accessed = identify_most_accessed_endpoint(logs)
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(logs)
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV
    save_results_to_csv(ip_counts, most_accessed, suspicious_activity)

if __name__ == "__main__":
    main()
