import base64
import requests
import os
import json
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
import sys

gt_username = 'jahn321'
server_name = 'secure-shared-store'

# These need to be created manually before you start coding.
node_certificate = os.getcwd() + '/certs/' + os.getcwd().rpartition('/')[2] + '.crt'
node_key = os.getcwd() + '/certs/' + os.getcwd().rpartition('/')[2] + '.key'

checked_out = []


''' <!!! DO NOT MODIFY THIS FUNCTION !!!>'''


def post_request(server_name, action, body, node_certificate, node_key):
    """
        node_certificate is the name of the certificate file of the client node (present inside certs).
        node_key is the name of the private key of the client node (present inside certs).
        body parameter should in the json format.
    """
    request_url = 'https://{}/{}'.format(server_name, action)
    request_headers = {
        'Content-Type': "application/json"
    }
    response = requests.post(
        url=request_url,
        data=json.dumps(body),
        headers=request_headers,
        cert=(node_certificate, node_key),
    )
    with open(gt_username, 'wb') as f:
        f.write(response.content)

    return response


''' You can begin modification from here'''


def sign_statement(statement, user_private_key_file):
	key = RSA.import_key(open(user_private_key_file).read())
	h = SHA256.new(statement.encode())
	signature = pkcs1_15.new(key).sign(h)
	return signature


def login():
    """
        # TODO: Accept the
         - user-id
         - name of private key file(should be present in the userkeys folder) of the user.
        Generate the login statement as given in writeup and its signature.
        Send request to server with required parameters (Ex: action = 'login') using the
        post_request function given.
        The request body should contain the user-id, statement and signed statement.
    """

    successful_login = False

    while not successful_login:
        # get the user id from the user input or default to user1
        user_id = (input(" User Id: ") or "user1")

        # get the user private key filename or default to user1.key
        private_key_filename = (input(" Private Key Filename: ") or "user1.key")

        # complete the full path of the user private key filename
        # /home/cs6238/Desktop/Project4/client1/userkeys/{private_key_filename}
        user_private_key_file = '/home/cs6238/Desktop/Project4/client1/userkeys/'+private_key_filename

        # get the client id from the current working path
        client_id = node_key[node_key.rfind("/")+1:-4]
        if client_id != "client1" and client_id !="client2":
        	print("No valid client")
		
        # create the statement
        statement = client_id+' as '+user_id+' logs into the Server'
        signed_statement = sign_statement(statement, user_private_key_file)

        body = {
            'user-id': user_id,
            'statement': statement,
            'signed-statement': base64.b64encode(signed_statement).decode("utf8")
        }

        server_response = post_request(server_name, 'login', body, node_certificate, node_key)
		
        if server_response.json().get('status') == 200:
            successful_login = True
        else:
            print(server_response.json().get('message', "Try again"))
	
    return server_response.json()


def checkin(session_token):
    """
        # TODO: Accept the
         - DID: document id (filename)
         - security flag (1 for confidentiality  and 2 for integrity)
        Send the request to server with required parameters (action = 'checkin') using post_request().
        The request body should contain the required parameters to ensure the file is sent to the server.
    """
    filename = input("Which file name?")
    cwd = os.getcwd()
    filepath = cwd+'/documents/checkin/'+filename
    checkoutpath = cwd+'/documents/checkout/'+filename
    checkin = os.path.exists(filepath)
    checkout = os.path.exists(checkoutpath)
    if not checkin and not checkout:
    	print("No such file")
    	return False
    elif checkout:
    	os.system('mv '+checkoutpath+' '+filepath)
    
     
    security_flag = input("Which integrity you want? 1: confidentiality, 2: integrity: ")
    # body = {'DID' : filename,'SecurityFlag' : security_flag}
    body = {'DID' : filename,'SecurityFlag' : security_flag, 'Content' : open(filepath).read(), 'token': session_token}
    server_response = post_request(server_name, 'checkin', body, node_certificate, node_key)
    if server_response.json().get('status') == 200:
    	print("Checkin is successful")
    else:
    	print(server_response.json().get('status'), "Checkin failed...")
    return


def checkout(session_token):
    """
        # TODO:
        Send request to server with required parameters (action = 'checkout') using post_request()
    """
    filename = input("Which file name?")
    body = {'DID' : filename,'token': session_token}
    server_response = post_request(server_name, 'checkout', body, node_certificate, node_key)
    _response =server_response.json()
    if server_response.json().get('status') == 200:
    	content = server_response.json().get('contents')
    	filepath = os.getcwd()+'/documents/checkout/'+filename
    	checked_out.append(filepath)
    	with open(filepath, 'w') as f:
    		f.write(content)
    	print("Checkout is successful")
    else:
    	print(_response.get('message'))
    return


def grant(session_token):
    """
        # TODO:
         - DID
         - target user to whom access should be granted (0 for all user)
         - type of access to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
         - time duration (in seconds) for which access is granted
        Send request to server with required parameters (action = 'grant') using post_request()
    """
    filename = input("Which file for grant? :")
    targetuser = input("To whom? :")
    right = input("Which right? 1 - Checkin, 2 - Checkout, 3 - Both :")
    t = input("How long?")
    
    body = {'DID': filename, 'TUID': targetuser, 'R': right, 'T': t, 'token': session_token}
    server_response = post_request(server_name, "grant",body, node_certificate, node_key)
    _response = server_response.json()
    status_code = _response.get('status')
    print(_response.get('message'))
    return


def delete(session_token):
    """
        # TODO:
        Send request to server with required parameters (action = 'delete')
        using post_request().
    """
    filename = input("Which file to Delete? :")
    body = {'DID': filename, 'token': session_token}
    server_response = post_request(server_name, "delete",body, node_certificate, node_key)
    status = server_response.json().get('status')
    if status == 200:
    	print("Delete Successful.")
    elif status == 702:
    	print("Access Denied.")
    elif status == 704:
    	print("Delete failed since file not found on the server")
    else:
    	print("Failed for other reason....")

    return


def logout(session_token):
    """
        # TODO: Ensure all the modified checked out documents are checked back in.
        Send request to server with required parameters (action = 'logout') using post_request()
        The request body should contain the user-id, session-token
    
    for item in checked_out:
    	filename = item[item.rfind('/')+1:]
    	ctime = os.path.getctime(item)
    	mtime = os.path.getmtime(item)
    	if ctime != mtime:
    		body = {'DID' : filename,'SecurityFlag' : "2", 'Content' : open(item).read(), 'token': session_token}
    		server_response = post_request(server_name, 'checkin', body, node_certificate, node_key)
    		status = server_response.json().get('status')
    		if status == 200:
    			print("Checked out all modified "+filename)
    		else:
    			print("Failed to check out modified "+filename)
    		return 
    """
    body = {'token': session_token}
    server_response = post_request(server_name, 'logout', body, node_certificate, node_key)
    if server_response.json().get('status') == 200:
    	print(server_response.json().get('message'))
    	#sys.exit(1)
    else:
    	print(server_response.json().get('message'))
    return

def print_main_menu():
    """
    print main menu
    :return: nothing
    """
    print(" Enter Option: ")
    print("    1. Checkin")
    print("    2. Checkout")
    print("    3. Grant")
    print("    4. Delete")
    print("    5. Logout")
    return


def main():
    """
        # TODO: Authenticate the user by calling login.
        If the login is successful, provide the following options to the user
            1. Checkin
            2. Checkout
            3. Grant
            4. Delete
            5. Logout
        The options will be the indices as shown above. For example, if user
        enters 1, it must invoke the Checkin function. Appropriate functions
        should be invoked depending on the user input. Users should be able to
        perform these actions in a loop until they logout. This mapping should
        be maintained in your implementation for the options.
    """

    # Initialize variables to keep track of progress
    server_message = 'UNKNOWN'
    server_status = 'UNKNOWN'
    session_token = 'UNKNOWN'
    is_login = False

    #test()
    #return
    login_return = login()

    server_message = login_return['message']
    server_status = login_return['status']
    session_token = login_return['session_token']


    print("\nThis is the server response")
    print(server_message)
    print(server_status)
    print(session_token)

    if server_status == 200:
        is_login = True

    while is_login:
        print_main_menu()

        user_choice = input()

        if user_choice == '1':
            checkin(session_token)
        elif user_choice == '2':
            checkout(session_token)
        elif user_choice == '3':
            grant(session_token)
        elif user_choice == '4':
            delete(session_token)
        elif user_choice == '5':
            logout(session_token)
            is_login = False #Is this right?
            main()
        else:
            print('not a valid choice')


if __name__ == '__main__':
    main()
