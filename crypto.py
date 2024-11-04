import requests
import ssl
import socket
from urllib.parse import urlparse

# List of known weak ciphers
weak_ciphers = [
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_RSA_WITH_AES_128_CBC_SHA',
    'TLS_RSA_WITH_AES_256_CBC_SHA'
]


def check_https(url):
    """Check if the URL uses HTTPS."""
    parsed_url = urlparse(url)
    return parsed_url.scheme == "https"


def check_ssl_configuration(url):
    """Check SSL/TLS certificate configuration and expiration date."""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443

        # Create an SSL context
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

                # Get cipher suite details
                cipher_name = cipher[0]
                if cipher_name in weak_ciphers:
                    return f"Weak Cipher Suite Detected: {cipher_name}", False
                else:
                    return f"Cipher Suite in Use: {cipher_name}", True

    except Exception as e:
        return f"SSL Error: {str(e)}", False


def perform_ssl_check(url):
    """Perform SSL/TLS configuration check and return the results."""
    cert_info, ssl_status = check_ssl_configuration(url)
    if ssl_status:
        return f"{cert_info}\nSSL Configuration: Secure", True
    else:
        return f"{cert_info}\nSSL Configuration: Vulnerable", False


def scan_website(url):
    """Perform security checks on the given URL."""
    results = {}
    results['HTTPS'] = check_https(url)
    ssl_result, ssl_status = perform_ssl_check(url)
    results['SSL Configuration'] = ssl_result

    return results


if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    results = scan_website(target_url)

    output_file = "security_check_results.txt"
    with open(output_file, 'w') as file:
        file.write("Security Check Results:\n")
        for check, result in results.items():
            file.write(f"{check}: {result}\n")

    print(f"Results written to {output_file}")