from flask import Flask, request, jsonify
from flask_restful import Resource, Api, reqparse
import os
import base64
from uuid import uuid4
import time 
'''
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.Random import get_random_bytes
'''
import json
import rsa
import sys

secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)
aes_key_dic = {}
session_token_dic = {}
#token_client = {} # Dictionary for token<->client
file_dic = dict() # Dictionary for did, owner and flag
grant_dic = dict()
class File:
	def __init__(self, u_id:str, flag: str, data: str = ""):
		self.u_id = u_id
		self.flag = flag
		self.data = data
		self.grant = list()
	
class welcome(Resource):
    def get(self):
        return "Welcome to the secure shared server!"


def verify_statement(statement, signed_statement, user_public_key_file):
	key = RSA.import_key(open(user_public_key_file).read())
	h = SHA256.new(statement.encode())
	
	try:
		pkcs1_15.new(key).verify(h, signed_statement)
		print ("signature is valid.")
		return True
	except:
		print("signature is not valid.")
		return False

class login(Resource):
    def post(self):
        data = request.get_json()
        
        # Information coming from the client
        user_id = data['user-id']
        statement = data['statement']
        signed_statement = base64.b64decode(data['signed-statement'])
        # complete the full path of the user public key filename
        # /home/cs6238/Desktop/Project4/server/application/userpublickeys/{user_public_key_filename}
        cwd = os.getcwd()
        user_public_key_file = cwd + '/userpublickeys/' + user_id + '.pub'

        success = verify_statement(statement, signed_statement, user_public_key_file)
        print(success)
        if success:
            session_token = uuid4()  
            session_token_dic[str(session_token)] = user_id
            #token_client[str(session_token)] = client_name
            
            # Similar response format given below can be used for all the other functions
            response = {
                'status': 200,
                'message': 'Login Successful',
                'session_token': session_token,
            }
        else:
            response = {
                'status': 700,
                'message': 'Login Failed',
                'session_token': "INVALID",
            }
        return jsonify(response)


class checkout(Resource):
    """
    Expected response status codes
    1) 200 - Document Successfully checked out
    2) 702 - Access denied checking out
    3) 703 - Check out failed due to broken integrity
    4) 704 - Check out failed since file not found on the server
    5) 700 - Other failures
    """
    def post(self):
      data = request.get_json()
      filename = data['DID']
      token = data['token']
      filepath = os.getcwd()+'/documents/'+filename
      now_dir = os.getcwd()
      server_key = open(now_dir[:now_dir.rfind('/')]+'/certs/secure-shared-store.key').read()
      server_pub_key = open(now_dir[:now_dir.rfind('/')]+'/certs/secure-shared-store.pub').read()
      user_id = session_token_dic[str(token)]
      
      if not os.path.exists(filepath):
        response = {'status':704, 'message': 'Check out failed since file not found on the server'}
        return jsonify(response)
      file_content = open(filepath, 'rb').read()
      grant_key = (filename, user_id)
      
      if os.path.exists(os.getcwd()+'/documents/'+filename):
        file_data_read = open(os.getcwd()+'/documents/meta_'+filename, 'rb').read()
        file_flag = file_data_read.split(b'\n')[2].decode('utf-8')
        user_name = file_data_read.split(b'\n')[1].decode('utf-8')
        file_data = file_data_read.split(b';;;')[1]
        
        #grant_data = file_data_read.split(b'\n')[-1].decode('utf-8')
        #print(grant_data)
        #print("asdfasfasfasfasdf", type(grant_data))
        #print(json.loads(grant_data))
       
        if user_name == user_id:
          pass
          
        elif grant_key in grant_dic.keys():
          
          grant = grant_dic[grant_key]
          now = time.time()
          right = grant[0]
          start = grant[1]
          end = grant[2]
          print(right, type(right))
          
          if (right != "2") and (right!= "3"):
            
            response = {'status':702, 'message': 'Access denied checking out'}
            return jsonify(response)
          elif (right =="2" or right =="3") and (now>=end):
            
            response = {'status':702, 'message': 'Access denied checking out'}	
            return jsonify(response)
          elif (right =="2" or right =="3") and (now>start and now<end):
            pass
        else:
          response = {'status':702, 'message': 'Access denied checking out'}	
          return jsonify(response)
            
      print(file_flag)
      if (file_flag=="1"):
        
        server_key = RSA.importKey(server_key)
        decryptor = PKCS1_v1_5.new(server_key)
        sentinal = get_random_bytes(16)
        #print(file_data)
        
        _key = decryptor.decrypt(file_data, sentinal, 16)
        #aes_key = aes_key_dic[file_data]
        
        aes_key = aes_key_dic[filename]
        nonce= file_data_read.split(b';;;')[2]
        cipher = AES.new(_key, AES.MODE_EAX,nonce)
        plain_contents = cipher.decrypt(file_content).decode('utf-8')
        
      elif (file_flag=="2"):
        
        key = RSA.import_key(server_pub_key)
        h = SHA256.new(file_content)
        try:
        	pkcs1_15.new(key).verify(h, file_data)
        	plain_contents = file_content.decode('utf-8')
        except:
        	response = {'status':703, 'message': 'Check out failed due to broken integrity'}
        	return jsonify(response)
      response= {'status': 200,'message': 'Document Successfully checked out','contents': plain_contents}
      return jsonify(response)
      '''
      except:
        response = {'status':700, 'message':'Other failures'}
        return jsonify(response)      
      '''
class checkin(Resource):
    """
    Expected response status codes:
    1) 200 - Document Successfully checked in
    2) 702 - Access denied checking in
    3) 700 - Other failures
    """
    def post(self):
    	self.data = request.get_json()
    	self.filename = self.data['DID']
    	self.security_flag = self.data['SecurityFlag']
    	self.content = self.data['Content']
    	self.encoded_content = self.content.encode('utf-8')
    	self.token = self.data['token']
    	self.now_dir = os.getcwd()
    	self.filepath = os.getcwd()+'/documents/'+self.filename+'.txt' 
    	server_key = RSA.import_key(open(self.now_dir[:self.now_dir.rfind('/')]+'/certs/secure-shared-store.key').read())
    	server_pub_key = RSA.import_key(open(self.now_dir[:self.now_dir.rfind('/')]+'/certs/secure-shared-store.pub').read())
    	self.user_id = session_token_dic[str(self.token)]
    	self._file = File(self.user_id, self.security_flag)
    	if os.path.exists(os.getcwd()+'/documents/'+self.filename):
		    self.file_data_read = open(os.getcwd()+'/documents/meta_'+self.filename, 'rb').read()
		    self.user_name = self.file_data_read.split(b'\n')[1].decode('utf-8')
		    if self.user_name != self.user_id :
		    	if (self.filename, self.user_id) in grant_dic.keys():
		    		self.grant = grant_dic[(self.filename, self.user_id)]
		    		now = time.time()
		    		right = self.grant[0]
		    		start = self.grant[1]
		    		end = self.grant[2]
		    		if right != "1" or right != "3":
		    			response = {'status':'702', 'message':'Access denied checking in'}
		    			return jsonify(response)
			    	elif now not in (start, end):
			    		response = {'status':'702', 'message':'Access denied checking in'}
			    		return jsonify(response)
    			else:
    				response = {'status':'702', 'message':'Access denied checking in'}
    				return jsonify(response)
    	if self.security_flag =="1":
    		#key = b'Sixteen secret key12345678'
    		aes_key =get_random_bytes(16)
    		cipher = AES.new(aes_key, AES.MODE_EAX)
    		nonce = cipher.nonce
    		print("aes_key at checkin")
    		print(aes_key)
    		ciphertext, tag = cipher.encrypt_and_digest(self.encoded_content)
    		encryptor = PKCS1_v1_5.new(server_pub_key)
    		encrypted_cipher = encryptor.encrypt(aes_key)
    		
    		#aes_key_dic[encrypted_cipher] = aes_key
    		aes_key_dic[self.filename] = aes_key
    		
    		print("ciphertext :")
    		print(ciphertext)
    		
    		self._file.data = encrypted_cipher+b";;;"+nonce
    		self.content = ciphertext
    	elif self.security_flag =="2":
    		h = SHA256.new(self.encoded_content)
    		signed_data = pkcs1_15.new(server_key).sign(h)
    		#print("At checkin : signed data = "+ str(signed_data))
    		self.content = self.encoded_content
    		self._file.data = signed_data
    	else: 
    		print("Invalid security flag")
    		return False
    	file_dic[self.filename] = self._file
    	os.system("touch "+os.getcwd()+'/documents/'+self.filename)
    	with open(os.getcwd()+'/documents/'+self.filename, 'wb') as f:
    		f.write(self.content)
    	self.write_data = ""
    	self.u_id_save = (self._file.u_id+"\n").encode()
    	self.flag_save = (self._file.flag).encode()
    	self.data_save = self._file.data
    	self.filename_save = (self.filename+"\n").encode()
    	self.write_data = self.filename_save+self.u_id_save+self.flag_save+b'\n;;;'+self.data_save
    	metafilepath = os.getcwd()+'/documents/meta_'+self.filename
    	os.system('touch '+metafilepath)
    	with open(os.getcwd()+'/documents/meta_'+self.filename, 'wb') as f:
    		f.write(self.write_data)
    	response = {'status': 200, 'message': 'Document Successfully checked in'}
    	return jsonify(response)


class grant(Resource):
    """
        Expected response status codes:
        1) 200 - Successfully granted access
        2) 702 - Access denied to grant access
        3) 700 - Other failures
    """
    def post(self):
        try:
        	data = request.get_json()
        	token = data['token']
        	did = data['DID']
        	metafilepath = os.getcwd()+'/documents/meta_'+did
        	tuid = data['TUID']
        	right = data['R']
        	t = data['T']
        	now = time.time()
        	#grant_key = tuid
        	grant_key = (did, tuid)
        	grant_tuple_time = (right, now, now+float(t))
	        _grant_ = dict()
	        _grant_[grant_key] = grant_tuple_time
        	u_id = session_token_dic[token]
        	
        	_file = file_dic[did]
        	
        	if _file.u_id != u_id:
        		response = {'status':702, 'message': 'Access denied to grant access' }
        		return jsonify(response)
        	grant_dic[grant_key] = grant_tuple_time
        	print(grant_dic)
        	#with open(metafilepath, 'a+b') as f:
        		#print("openopenopen")
        		#f.write(b"\n")
        		#f.write(json.dumps(_grant_).encode())
        		#f.write(("\n"+str(_grant_)).encode())
        	response ={'status': 200, 'message': 'Successfully granted access'}
	        return jsonify(response)
        except:
	        response = {'status':700, 'message' : 'Other failures'}
	        return jsonify(response)
		

class delete(Resource):
    """
        Expected response status codes:
        1) 200 - Successfully deleted the file
        2) 702 - Access denied deleting file
        3) 704 - Delete failed since file not found on the server
        4) 700 - Other failures
    """
    
    def post(self):
        data = request.get_json()
        did = data['DID'] 
        token = data['token']
        filepath = os.getcwd()+'/documents/'+did
        metafilepath = os.getcwd()+'/documents/meta_'+did
        if not os.path.exists(filepath):
        	response = {'status':704, 'message':"Delete failed since file not found on the server"}
        	return jsonify(response)
        user_id = session_token_dic[token]
        username = (open(metafilepath, 'rb').read()).split(b'\n')[1].decode('utf-8')
        print(user_id, username)
        if user_id != username:
        	response = {'status':702, 'message': "Access Denied."}
        	return jsonify(response)
        try:
        	
        	os.system('rm '+filepath)
        	
        	os.system('rm '+metafilepath)
        	response = {'status': 200,'message': 'Successfully deleted the file'}
        	return jsonify(response)
        except:
        	response = {'status': 700,'message': 'Failed for other reasons..'}
        	return jsonify(response)

class logout(Resource):
    def post(self):
        """
            Expected response status codes:
            1) 200 - Successfully logged out
            2) 700 - Failed to log out
        """
        try:
        	data = request.get_json()
        	token = data['token']
        	del session_token_dic[token]
        	response = {'status': 200,'message': 'Successfully logged out'}
        except:
        	response = {'status':700, 'message': 'Failed to log out'}
        return jsonify(response)


api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')


def main():
    secure_shared_service.run(debug=True)


if __name__ == '__main__':
    main()