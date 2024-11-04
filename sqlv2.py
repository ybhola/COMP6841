import subprocess

def run_sqlmap(url):
    """Run SQLMap on the given URL and return the output."""
    sqlmap_path = '/Users/yashikabhola/Desktop/WebsiteToolKit/sqlmap/sqlmap.py'  # Update this path
    try:
        # Run SQLMap command with additional options for thorough scanning
        result = subprocess.run(
            ['python3', sqlmap_path, '-u', url, '--batch', '--crawl=2', '--level=5', '--risk=3', '--dump'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Check for errors
        if result.returncode != 0:
            print("Error running SQLMap:")
            print(result.stderr)
            return None

        return result.stdout

    except FileNotFoundError:
        print("SQLMap not found. Please ensure it is installed and the path is correct.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def parse_sqlmap_output(output):
    """Parse the SQLMap output and extract vulnerabilities."""
    vulnerabilities = []

    if "Parameter" in output:
        lines = output.splitlines()
        for line in lines:
            if "Parameter" in line or "Type" in line or "Payload" in line:
                vulnerabilities.append(line)

    return vulnerabilities

def write_results_to_file(vulnerabilities, output_file):
    """Write the detected vulnerabilities to a specified output file."""
    with open(output_file, 'w') as file:
        if vulnerabilities:
            file.write("Potential SQL Injection Vulnerabilities Found:\n")
            for message in vulnerabilities:
                file.write(f"{message}\n")
        else:
            file.write("No potential SQL injection vulnerabilities found.\n")

if __name__ == "__main__":
    target_url = input("Enter the URL to scan for SQL injection (e.g., http://example.com/page.php?id=1): ")
    output_file = input("Enter the name for the output file (default: sql_injection_results.txt): ") or 'sql_injection_results.txt'
    
    # Run SQLMap on the target URL
    output = run_sqlmap(target_url)
    
    if output:
        vulnerabilities = parse_sqlmap_output(output)
        write_results_to_file(vulnerabilities, output_file)
        print(f"Results written to {output_file}")
