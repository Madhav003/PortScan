print("hello world")

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







# main
if __name__ == "__main__":
    #test parse_ports function and tcp_connect_scan function against 100.73.129.93
    target = "100.73.129.93"
    ports = parse_ports("22,80,443,8080,1000-1005,8096,2283")
    for port in ports:
        if tcp_connect_scan(target, port, 1):
            print(f"Port {port} is open on {target}")
        else:
            print(f"Port {port} is closed on {target}")