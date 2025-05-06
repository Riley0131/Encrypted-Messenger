# Encrypted Messenger
Developed by Riley O'Shea & Aidan Meshberg

## Required Packages
socket, json, argparse, os, base64, Fernet, Cryptography 
Python packages

## Instructions
### Server
1. Download any required packages
2. In a terminal or your server's terminal load all of the html templates and the server.py files
3. Make any adjustments to the socket address to match your public site.
4. Run "python3 server.py" to run the server
5. In another terminal run the webUI "python3 web_ui.py"

### Client
1. Access the desired socket address (defined by the server file - map to your website) 
2. In a web browser enter the correct address
3. Register a user by accessing YOURSITE/register
4. Log in that user at YOURSITE/login
5. To send a message select the "Send a Message" link, enter the recipients name and your message
Note: recipient must be a registered user
6. View any messages sent to you by visiting YOURSITE/inbox