def check_hosts(subnet_mask : str):
    from netaddr import IPNetwork
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    mask = subnet_mask
    network = IPNetwork('/'.join([ip_address, mask]))
    generator = network.iter_hosts()
    st = ''
    for i in list(generator):
        st += str(i) + '\n'
    return st


def main():
    print(check_hosts("255.255.0.0"))

main()