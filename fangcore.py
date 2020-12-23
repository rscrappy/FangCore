'''
November 2020 - FangCore - Jacob Scrapchansky
FangCore is a python library built for creating highly customizable Operating systems.
It has incredibly high-level command parsing, script management, remote terminal, and distributed processing tools
'''

'''
to add:
V1.2:
Filer

Add Html ssl

Make HTTP resilient 


V1.3:
FangNet
HTTP 2.0 support
HTTP timeouts

'''
VERSION = "v1.2Beta"

import socket
import threading
import ssl

class FangCore:
	def __init__(self, *enabled_builtins):
		self.command_bindings = []
		self.load_defines = {}
		self.extension_defines = {}
		self.extensions = []
		self.appfiles = []
		self.limitlist_function = None

		if "load" in enabled_builtins:
			self.bind_command("load", self._default_appfile_loader)
		if "quit" in enabled_builtins:
			self.bind_command("quit", quit)


	def command(self, string, blacklist=None, whitelist=None):
		ignore_state = False
		letter = 0
		try:
			string = string.strip()
			string = string.replace("\r\n", " ")
			string = string.replace("\n", " ")
		except Exception:
			return
		final = [[],[],string,string]
		append_to_final = ""
		while True: #Command string Parser

			if letter == len(string): #Detect Ingnore and ignore exceptions
				break;
			if string[letter] == "\\":
				ignore_state = True
				letter += 1
				if letter == len(string):
					break
				if string[letter] == "\\":
					ignore_state = False
					append_to_final += "\\"

			current_letter = string[letter] # set constant to increase speed

			if current_letter == " " and not(ignore_state): #Separate command arguments by spaces
				final[0].append(append_to_final)
				append_to_final = ""

			elif current_letter == "-" and not(ignore_state): #Detect options
				if not(letter+1 == len(string)) and not(string[letter+1] == " "):
					option_add = ""
					while True:
						if letter+1 == len(string) or string[letter]==" ":
							break
						
						letter += 1
						option_add += string[letter]
						
					final[1].append(option_add.strip())


			else: #add letter to separation buffer
				append_to_final += current_letter

			ignore_state = False
			letter += 1
		final[0].append(append_to_final)
		# Complete Parsing

		#Clean up
		if (len(final[0][1:]) == 1):
			if final[0][1] == '':
				del final[0][1]

		if whitelist and blacklist: #Prioritize Whitelist if both are set
			blacklist = None

		exists = False #Check if command exists
		for command in self.command_bindings:
			if command[2] == final[2]:
				exists = True
		if not(exists):
			return final

		if blacklist: # check for command in blacklist if set
			if final[2] in blacklist:
				if self.limitlist_function:
					try:
						self.limitlist_function(final)
						return False
					except Exception:
						self.limitlist_function()
						return False
				else:
					return final

		if whitelist: # check for command in whitelist if set
			if not(final[2] in whitelist):
				if self.limitlist_function:
					try:
						self.limitlist_function(final)
						return False
					except Exception:
						self.limitlist_function()
						return False
				else:
					return final


		for command in self.command_bindings: #Begin command search
			if command[2].strip() == final[0][0]:
				if not(command[0]):
					try:
						command[1]([final[0][1:],final[1],final[2][:len(final[0][0])],final[2][len(final[0][0]):]]) # Execute without parameters
					except TypeError:
						command[1]()
				else:
					try:
						command[1]([final[0][1:],final[1],final[2][:len(final[0][0])],final[2][len(final[0][0]):]],command[0]) # Execute with param
					except TypeError:
						try:
							command[1](command[0])
						except TypeError:
							command[1]()
				return False
		return final


	def bind_command(self, command, call_function, call_function_param=None): #Bind a command to a call function, and the parameter will be fed into the function supplied
		if call_function_param == None: #Determine if parameter driven
			param_driven = False
		else: 
			param_driven = str(call_function_param)
		self.command_bindings.append([param_driven, call_function, str(command)]) #Add command to main list

	def set_limit_list_function(self, function):
		self.limitlist_function = function

	def set_load_print_pipe(self, print_function): #Set the print function of file loader
		self.load_defines['print'] = print_function

	def set_load_input_pipe(self, input_function): #Set the input function of file loader
		self.load_defines['input'] = input_function

	def set_extension_print_pipe(self, print_function): #Se the print function of the extension loader
		self.extension_defines['print'] = print_function

	def set_extension_input_pipe(self, input_function): #Set the input function of the extension loader
		self.extension_defines['input'] = input_function

	def extension_define(self, string, function): #Define or redefine a function/variable for the extension loader
		self.extension_defines[str(string)] = function

	def extension_define_delete(self, string): #Delete a defined function for the extension loader
		try:
			del self.extension_defines[str(string)]
		except Exception:
			pass

	def load_define(self, string, function): #Define or redefine a function/variable for the file loader
		self.load_defines[str(string)] = function

	def load_define_delete(self, string, function): #Delete a defined function for the file loader
		try:
			del self.load_defines[str(string)]
		except Exception:
			pass

	def create_extension(self, callsign, string, call_enable=True): #Create a system extension
		self.extensions.append([str(callsign), str(string)])
		if call_enable:
			self.bind_command(str(callsign), self._internal_extension_loader, str(callsign))


	def delete_extension(self, callsign): #Delete a certain extension
		for extension in range(len(self.extensions)):
			if self.extensions[extension][0] == str(callsign):
				del self.extensions[extension]
				return

	def clear_extensions(self): #Delete all extensions
		self.extensions = []

	def create_appfile(self, name, string, loadable=True): #Create an appfile
		self.appfiles.append([str(name), str(string), bool(loadable)])

	def delete_appfile(self, name): # Delete a certain Appfile
		for appfile in range(len(self.appfiles)):
			if self.appfiles[appfile][0] == str(name):
				del self.appfiles[appfile]
				return

	def clear_appfiles(self): # Delete all appfiles
		self.appfiles = []

	def run_extension(self, callsign, args=None, print_pipe=None, input_pipe=None, other_redefinitions=None): # run an extension externally
		if args == None:
			args = [[],[],str(callsign),""]
		extension_definitions = self.extension_defines
		extension_definitions['args'] = args
		if print_pipe:
			extension_definitions['print'] = print_pipe
		if input_pipe:
			extension_definitions['input'] = input_pipe
		if other_redefinitions:
			extension_definitions += other_redefinitions
		for extension in self.extensions:
			if extension[0] == str(callsign):
				exec(extension[1], extension_definitions)


	def run_appfile(self, name, print_pipe=None, input_pipe=None, other_redefinitions=None): #run an appfile externally
	 	load_definitions = self.load_defines
	 	if print_pipe:
	 		load_definitions['print'] = print_pipe
	 	if input_pipe:
	 		load_definitions['input'] = input_pipe
	 	if other_redefinitions:
	 		load_definitions += other_redefinitions
	 	for appfile in self.appfiles:
	 		if appfile[0] == str(name):
	 			if appfile[2]:
	 				exec(appfile[1], load_definitions)
	 				return True
	 			else:
	 				return False
	 	return False

	def set_defaults(self): #Load all default pipes, definitions, and functions
		self.extension_defines['print'] = print
		self.extension_defines['input'] = input
		self.load_defines['print'] = print
		self.load_defines['input'] = input



	def _internal_extension_loader(self, args, param):
		self.run_extension(param, args)

	def _default_appfile_loader(self, args):
		try:
			self.run_appfile(args[0][0])
		except Exception:
			pass
fang = FangCore #Legacy naming scheme adapter



class FangCoreTerminal: #A Class for creating FangCore Terminal Servers
	'''
	FangTerminal protocol
	5|priHello
	5|inpHello
	5|retHello
	14|redlocalhost 9000
	0|clr
	0|cte
	0|cre
	0|cls
	0|rfi
	0|refdata
	0|nre
	0|sfiname data
	'''

	def __init__(self, IP, Port, listener_max=10): #Initialize Libraries, define IP, Port, and set up request buffer

		self.IP = IP
		self.port = Port
		self.request_buffer = []
		self.max_listen = listener_max

	def start_server(self): #Start up the server on the desired address
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server.bind((self.IP, self.port))
		self.server.listen(self.max_listen)

	def close_server(self): #Close the server, capable of restarting
		self.server.shutdown(socket.SHUT_RDWR)
		self.server.close()
		

	def await_connection(self, timeout=None): #await for a connection to start, return client object, return False if failure or timeout
		if timeout:
			self.server.settimeout(timeout)

		try:
			client, address = self.server.accept()
			return _Fang_Terminal_Server_Client(client, address)
		except Exception:
			return False


class _Fang_Terminal_Server_Client:
	def __init__(self, client, address): #Initialize the client variables and objects
		self.client = client
		self.address = address
		self.connection_open = True

	def print(self, string):  #Print to client
		string = str(string)
		try:
			self.client.sendall(str((str(len(string)) + "|pri"+string)).encode())
		except Exception:
			self.connection_open = False

	def input(self, string="", timeout=None):
		self.send(str(len(string)) + "|inp" + str(string))
		try:
			if timeout:
				try:
					number = ""
					while 1:
						rec = self.recv(1, timeout)
						if rec == "|":
							break
						else:
							number += rec
					if self.recv(3) == "ret":
						return self.recv(int(number))
					else:
						self.recv(number)
						return ""
				except socket.timeout:
					return False
			else:
				number = ""
				while 1:
					rec = self.recv(1)
					if rec == "|":
						break
					else:
						number += rec
				if self.recv(3) == "ret":
					return self.recv(int(number))
				else:
					self.recv(number)
					return ""
		except TypeError:
			self.connection_open = False
			return False

	def clear(self): #Clear client terminal
		self.send("0|clr")


	def redirect(self, IP, port): #Redirects the client to another server
		sended = str(IP) + " " + str(port)
		self.send(str(len(sended)) + "|red" + sended)

	def request_file(self, timeout=None): #Request a file
		self.send("0|rfi")
		try:
			if timeout:
				try:
					number = ""
					while 1:
						rec = self.recv(1, timeout)
						if rec == "|":
							break
						else:
							number += rec
					if self.recv(3) == "ref":
						recved = self.client.recv(int(number))
						if not(recved):
							return False
						else:
							return recved
					else:
						self.client.recv(number)
						return False
				except socket.timeout:
					return False
			else:
				number = ""
				while 1:
					rec = self.recv(1, timeout)
					if rec == "|":
						break
					else:
						number += rec
				if self.recv(3) == "ref":
					recved = self.client.recv(int(number))
					if not(recved):
						return False
					else:
						return recved
				else:
					self.client.recv(number)
					return False
		except TypeError:
			self.connection_open = False
			return False


	def close(self): #Close client connection
		self.send("0|cls")
		self.client.close()
		self.connection_open = False



	def get_address(self): #Get client's address
		return self.address

	def test_connection(self, timeout=None): #test the connection
		self.send("0|cte")
		if timeout:
			self.client.settimeout(timeout)
		try:
			if self.client.recv(5).decode().strip() == "0|cre":
				return True
			else:
				return False
		except socket.timeout:
			return False
			self.connection_open = False
		except Exception:
			return False
			self.connection_open = False

	def connection_status(self): # Return the set connection status
		return self.connection_open

	def send(self, string): #Send a raw string
		try:
			self.client.sendall(str(string).encode())
		except Exception:
			self.connection_open = False

	def recv(self, number, timeout=None): #Recieve a raw string
		if timeout:
			self.client.settimeout(timeout)
		recieved = None
		try:
			recieved = self.client.recv(number)
		except socket.timeout:
			return False
		except Exception:
			pass
		if not recieved:
			self.connection_open = False
			return False
		else:
			return recieved.decode()


class FangCoreTerminalClient:
	'''
	FangTerminal protocol
	5|priHello
	5|inpHello
	5|retHello
	14|redlocalhost 9000
	0|clr
	0|cte
	0|cre
	0|cls
	'''
	def __init__(self): #initialize all methods and objects, as well as background thread
		self.print_method = self._placeholder_method
		self.input_method = self._placeholder_method
		self.clear_method = self._placeholder_method
		self.file_request_method = self._placeholder_method
		self.connected_ip = None
		self.connected_port = None
		self.client = None
		self.connected = False
		self.connection_handler = threading.Thread(target=self._backround_connection_handler)

	def connect(self, IP, port): #Connect to a server
		try:
			self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.client.connect((IP, int(port)))
			self.connected_ip = IP
			self.connected_port = int(port)
			self.connected = True
			self.connection_handler.start()
			return True
		except Exception:
			return False

	def disconnect(self): #disconnect from a server
		self.client.close()
		self.connected_ip = None
		self.connected_port = None
		self.connected = False

	def connection_status(self): #Check the connection status
		return self.connected

	def set_print_method(self, function): #Define the standard print method
		self.print_method = function

	def set_input_method(self, function): #Define the standard input method
		self.input_method = function

	def set_clear_method(self, function): #Define the standard clear method
		self.clear_method = function

	def set_file_request_method(self, function):
		self.file_request_method = function

	def _backround_connection_handler(self): #Runs in background thread processing requests
	    while self.connected:
	        try: 
	        	number = 0
	        	while True:
	        	    val = self.client.recv(1).decode()
	        	    if val == "|":
	        	    	break
	        	    else:
	        	    	number = int(str(number) + val)
	        	keyword = self.client.recv(3).decode()
	        	message = self.client.recv(number).decode()
	        	if keyword == "pri":
	        		self.print_method(message)
	        	if keyword == "inp":
	        		returner = str(self.input_method(message))
	        		self.client.sendall(str(str(len(returner)) + "|ret" + returner).encode())
	        	if keyword == "clr":
	        		self.clear_method()
	        	if keyword == "cte":
	        		self.client.sendall(b"0|cre")
	        	if keyword == "cls":
	        		self.connected = False
	        		self.connected_ip = None
	        		self.connected_port = None
	        		self.client.close()
	        		break
	        	if keyword == "red":
	        		self.disconnect()
	        		self.connect(message.split()[0], int(message.split()[1]))
	        	if keyword == "rfi":
	        		returner = self.file_request_method()
	        		if not(returner):
	        			returner = b""
	        		message = str(str(len(returner)) + "|ref").encode() + returner
	        		self.client.sendall(message)

	        except ConnectionResetError:
	        	self.connected = False
	        	self.connected_ip = None
	        	self.connected_port = None
	        	break





	def _placeholder_method(self, *args): # Placeholder method for undefined methods
		pass

class HTTPServer: # A Class for creating basic robust HTTP response servers
	def __init__(self):
		self.http_ip = None
		self.http_port = None
		self.http_sock = None
		self.http_running = False
		self.response_method = None
		self.clients = []
		self.awaiting_connections = []


	def set_response_method(self, method): # Set the response method that will be called every time a client connects and sends a request
		self.response_method = method

	def start_http_server(self, IP, port, service_threads=1, listen=10, recv_max=8192, buffer=8192): # Starts the HTTP Server
		self.http_ip = str(IP)
		self.http_port = int(port) 
		self.http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.http_sock.bind((self.http_ip, self.http_port))
		self.http_sock.listen(int(listen))

		self.http_running = True
		self.current_id = 0

		thread = threading.Thread(target=self._http_connection_handler)
		thread.start()
		for iden in range(int(service_threads)):
			thread = threading.Thread(target=self._http_connection_servicer, args=(iden, service_threads-1, recv_max, buffer))
			thread.start()

		

	def stop_http_server(self): # Stop the HTTP Server
		self.http_running = False

	def _http_connection_handler(self): # Background thread that takes connections
		while self.http_running:
			client, address = self.http_sock.accept()
			self.awaiting_connections.append([client, address])
			

	def _http_connection_servicer(self, iden, max_id, max_recv, buffer): # Background thread that services connections
		while self.http_running:
			send = True
			while (len(self.awaiting_connections) == 0) or (self.current_id != iden):
				if not(self.http_running):
					return
			
			
			try:
				current = self.awaiting_connections[0]
				del self.awaiting_connections[0]
			except Exception:
				send = False

			if self.current_id == max_id:
				self.current_id = -1
			self.current_id += 1

			if send:
				try:
					client_obj = _HTTP_client(current[1], current[0], "HTTP", max_recv, buffer)
					self.response_method(client_obj)
					current[0].sendall(client_obj._render_page())
					current[0].close()
				except Exception:
					pass

class _HTTP_client: # The Client object that is sent to the response method that takes care of what is responded
	def __init__(self, address, client_object, http_or_https, max_read, buffer): # Initialize the object
		self.client = client_object
		self.address = address
		self.http_state = http_or_https
		self.tags = []

		read = b""
		for _ in range(round(max_read/buffer)):
			read += self.client.recv(buffer)

		temp_tags = read.decode().replace("\r\n", "\n").split("\n\n")[0].split("\n")[1:]
		for raw_tag in temp_tags:
			self.tags.append(raw_tag.split(": "))
		
		self.raw = read
		self.request = read.decode().split("\n")[0]
		self.http_version = None
		if " HTTP/1.1" in read.decode():
			self.http_version = "HTTP/1.1"

		self.request_type = self.request.split(" ")[0]
		self.split_request = read.decode().split("\r\n")[0].replace("GET ", "").replace(" HTTP/1.1", "").replace(" HTTP/2.0", "").split("/")
		self.split_request = [i for i in self.split_request if i != ""] 


		self.override_response = None
		self.response_tags = []
		self.response_header = b"200 OK"
		self.page = b''
		

	def add_tag(self, tag_name, tag_contents): # Add an HTTP tag
		self.response_tags.append(tag_name +": " + tag_contents)

	def add_raw(self, byte_string): # Add a tag but specify it to be raw
		self.response_tags.append(byte_string)

	def set_page(self, byte_string): # set the page contents
		self.page = byte_string

	def set_response(self, byte_string): # Set the response and override all other set responses
		self.override_response = byte_string

	def set_response_header(self, byte_string):
		self.response_header = byte_string

	def get_final_response(self):
		return self._render_page()

	def _render_page(self):
		if self.override_response:
			return self.override_response
		final = b"HTTP/1.1 " + self.response_header
		for tag in self.response_tags:
			final += tag + "\r\n"
		final += b"\r\n\r\n"
		final += self.page
		return final