import socket
import ssl

try:
    # Versuch, eine SSL-Verbindung aufzubauen und das Zertifikat zu erhalten
    context = ssl.create_default_context()
    with socket.create_connection(("pdms.atliwest.local", 443)) as sock:
        with context.wrap_socket(sock, server_hostname="pdms.atliwest.local") as ssock:
            cert = ssock.getpeercert()
            cert_present = 'Ja' if cert else 'Nein'
except Exception as e:
    cert_present = 'Nein'

print(cert_present)
