import socket
import json
import argparse

HOST = '127.0.0.1'  # adjust if server is on a different host
PORT = 12345       # must match server port
BUFFER_SIZE = 4096


def send_request(request):
    """
    Sends the JSON request to the server and returns the parsed JSON response.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(json.dumps(request).encode('utf-8'))
        data = sock.recv(BUFFER_SIZE)
        if not data:
            raise ConnectionError('No response received from server')
        return json.loads(data.decode('utf-8'))


if __name__ == '__main__':
    #controls for the client with different functions such as send, register, and get
    parser = argparse.ArgumentParser(description='Simple client for encrypted messaging server')
    parser.add_argument('--action', choices=['register', 'send', 'get'], required=True,
                        help='Action to perform: register a user, send a message, or get messages')
    parser.add_argument('--username', required=True, help='Username')
    parser.add_argument('--password', required=True, help='Password')
    parser.add_argument('--to', help='Recipient username (required for send)')
    parser.add_argument('--message', help='Message text (required for send)')
    args = parser.parse_args()

    req = {
        'action': args.action,
        'username': args.username,
        'password': args.password
    }

    #send function, will collect a message, encrypt it, and send it to the server
    if args.action == 'send':
        if not args.to or not args.message:
            print('Error: --to and --message are required for send')
            exit(1)
        req['to'] = args.to
        req['message'] = args.message

    try:
        response = send_request(req)
    except Exception as e:
        print(f'Error communicating with server: {e}')
        exit(1)

    # Pretty-print the server response
    print(json.dumps(response, indent=2))
