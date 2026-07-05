print("hello world")
import socket

def parse_ports(port_str, top_ports=None):
    """Parse a string of ports and return a list of integers. handles ranges(-) and ports (,)
    handle a -top-ports N flag where N is the number of top ports to scan from the 100 most common ports. If N is not specified, it defaults to all ports.
"""
    ports = []
    common = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

    if port_str == "":
        if top_ports is None:

            ports.extend(common)
            return ports
        else:
            top_ports = int(top_ports)

        if top_ports > 0 and top_ports <= 20:
            ports.extend(common[:top_ports])
        else:
            raise ValueError("top_ports must be between 1 and 20")
        return ports
    else:
        for part in port_str.split(','):
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))

    return ports
    
def tcp_connect_scan(target, port, timeout):
    """Perform a TCP connect scan on the specified target and port."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((target, port))
    sock.close()
    return result == 0


def scan_range_threaded(target, ports, max_threads=100, timeout=1):
    """multithreading to make the scan faster. use ThreadPoolExecutor to scan ports in parallel."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    results = {}
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(tcp_connect_scan, target, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                result = future.result()
                results[port] = result
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
                results[port] = False
    return results


def get_service_name(port):
    #does an offline lookup of the expected service name
    try:
        return socket.getservbyport(port, 'tcp')
    except OSError:
        return "unknown"
    

def grab_banner(sock, port, timeout):
    #Grab the banner from a service running on the specified port.
    sock.settimeout(timeout)
    banner = None
    try:
        if port in [80, 443, 8080]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode()
        else:
            banner = sock.recv(1024).decode()
    except socket.timeout:
        pass
    finally:
        sock.close()
    return banner



# main
if __name__ == "__main__":
    #test all functions against 100.73.129.93
    target = "100.73.129.93"
    ports = parse_ports("22,80,443,8080,1000,8096,2283")
    results = scan_range_threaded(target, ports, max_threads=10, timeout=1)
    for port, is_open in results.items():
        service_name = get_service_name(port)
        if is_open:
            print(f"Port {port} is open (Service: {service_name})")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target, port))
            banner = grab_banner(sock, port, timeout=1)
            if banner:
                print(f"Banner for port {port}: {banner}")
            else:
                print(f"No banner received for port {port}")
        else:
            print(f"Port {port} is closed (Service: {service_name})")