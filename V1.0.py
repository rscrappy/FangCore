'''
November 2020 - FangCore - Jacob Scrapchansky
FangCore is a python library built for creating highly customizable Operating systems.
'''

VERSION = "v1.0"


class fang:
	def __init__(self, *enabled_builtins):
		self.command_bindings = []
		self.load_defines = {}
		self.extension_defines = {}
		self.extensions = []
		self.appfiles = []

		if "load" in enabled_builtins:
			self.bind_command("load", self._default_appfile_loader)
		if "quit" in enabled_builtins:
			self.bind_command("quit", quit)


	def command(self, string):
		ignore_state = False
		letter = 0
		string = string.strip()
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