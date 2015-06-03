from Tkinter import *
import tkFileDialog
import os
#from ttk import Frame, Button, Style, Entry, Radiobutton


class gui(Frame):
	def __init__(self, parent):
		Frame.__init__(self, parent)   
		self.parent = parent
		self.createUI()
	
	def select_container(self):
		filename = tkFileDialog.askopenfilename()
		if os.path.isfile(filename):
			self.container_entry.delete(0,END)
			self.container_entry.insert(0,filename)
			
	def select_vol(self):
		filename = tkFileDialog.askopenfilename()
		if os.path.isfile(filename):
			self.Volatility_entry.delete(0,END)
			self.Volatility_entry.insert(0,filename)
	
	def select_image(self):
		filename = tkFileDialog.asksaveasfilename(defaultextension='.dd',filetypes=[('Raw Image', '.dd')])
		self.image_entry.delete(0,END)
		self.image_entry.insert(0,filename)
	
	def image(self):
		#import image
		#run image with options
		pass
	
	def update_options(self):
		if self.mode.get() == "key":
			#enable key options and disable others
			self.password_entry.config(state='disable')
			if 'aes' in self.encryption_mode.get():
				self.aes_entry.config(state='normal')
			else:
				self.aes_entry.config(state='disable')
			if 'twofish' in self.encryption_mode.get():
				self.Twofish_entry.config(state='normal')
			else:
				self.Twofish_entry.config(state='disable')
			if 'serpent' in self.encryption_mode.get():
				self.Serpent_entry.config(state='normal')
			else:
				self.Serpent_entry.config(state='disable')
			self.Volatility_entry.config(state='disable')
			self.Volatility_button.config(state='disable')
			self.hash_mode_ripemd.config(state='disable')
			self.hash_mode_sha.config(state='disable')
			self.hash_mode_whirlpool.config(state='disable')
			self.vera_checkbox.config(state='disable')
			self.backup_checkbox.config(state='disable')
			self.hidden_checkbox.config(state='disable')
			self.force_checkbox.config(state='disable')
			self.offset_entry.config(state='normal')
			self.datasize_entry.config(state='normal')
		elif self.mode.get() == "pwd":
			#enable pwd options and disable others
			self.password_entry.config(state='normal')
			self.aes_entry.config(state='disable')
			self.Twofish_entry.config(state='disable')
			self.Serpent_entry.config(state='disable')
			self.Volatility_entry.config(state='disable')
			self.Volatility_button.config(state='disable')
			self.hash_mode_ripemd.config(state='normal')
			self.hash_mode_sha.config(state='normal')
			self.hash_mode_whirlpool.config(state='normal')
			self.vera_checkbox.config(state='normal')
			self.backup_checkbox.config(state='normal')
			self.hidden_checkbox.config(state='normal')
			self.force_checkbox.config(state='normal')
			if self.force.get() == 1:
				self.offset_entry.config(state='normal')
				self.datasize_entry.config(state='normal')
			else:
				self.offset_entry.config(state='disable')
				self.datasize_entry.config(state='disable')
		else:
			#enable vol options and disable others
			self.password_entry.config(state='disable')
			self.aes_entry.config(state='disable')
			self.Twofish_entry.config(state='disable')
			self.Serpent_entry.config(state='disable')
			self.Volatility_entry.config(state='normal')
			self.Volatility_button.config(state='normal')
			self.hash_mode_ripemd.config(state='disable')
			self.hash_mode_sha.config(state='disable')
			self.hash_mode_whirlpool.config(state='disable')
			self.vera_checkbox.config(state='disable')
			self.backup_checkbox.config(state='disable')
			self.hidden_checkbox.config(state='disable')
			self.force_checkbox.config(state='disable')
			self.offset_entry.config(state='normal')
			self.datasize_entry.config(state='normal')
					
	def createUI(self):
		self.parent.title("pytruecrypt image")

		self.pack(fill=BOTH, expand=1)

		#create mode widgets
		self.mode_label = Label(self, text="Usage Mode:")
		self.mode_label.place(x=15, y=7)
		self.mode = StringVar()
		self.mode_password = Radiobutton(self, text="Password", variable=self.mode, value="pwd", command=self.update_options)
		self.mode_password.place(x=100, y=5)
		self.mode_key = Radiobutton(self, text="Key", variable=self.mode, value="key", command=self.update_options)
		self.mode_key.place(x=180, y=5)
		self.mode_volatility = Radiobutton(self, text="Volatility Key", variable=self.mode, value="vol", command=self.update_options)
		self.mode_volatility.place(x=226, y=5)
		self.mode.set("pwd")
		
		#create container entry
		self.container_label = Label(self, text="Container:")
		self.container_label.place(x=15, y=35)
		self.container_entry = Entry(self)
		self.container_entry.config(width=41)
		self.container_entry.place(x=100, y=35)
		self.container_button= Button(self, text="...", height=1, width=1,command=self.select_container)
		self.container_button.place(x=353, y=35)
		
		#create password entry
		self.password_label = Label(self, text="Password:")
		self.password_label.place(x=15, y=65)
		self.password_entry = Entry(self)
		self.password_entry.config(width=45)
		self.password_entry.place(x=100, y=65)
		
		#create AES key entry
		self.aes_label = Label(self, text="AES Key:")
		self.aes_label.place(x=15, y=95)
		self.aes_entry = Entry(self)
		self.aes_entry.config(width=45)
		self.aes_entry.place(x=100, y=95)
		
		#create Twofish key entry
		self.Twofish_label = Label(self, text="Twofish Key:")
		self.Twofish_label.place(x=15, y=125)
		self.Twofish_entry = Entry(self)
		self.Twofish_entry.config(width=45)
		self.Twofish_entry.place(x=100, y=125)
		
		#create Serpent key entry
		self.Serpent_label = Label(self, text="Serpent Key:")
		self.Serpent_label.place(x=15, y=155)
		self.Serpent_entry = Entry(self)
		self.Serpent_entry.config(width=45)
		self.Serpent_entry.place(x=100, y=155)
		
		#create Volatility key entry
		self.Volatility_label = Label(self, text="Volatility Key:")
		self.Volatility_label.place(x=15, y=185)
		self.Volatility_entry = Entry(self)
		self.Volatility_entry.config(width=41)
		self.Volatility_entry.place(x=100, y=185)
		self.Volatility_button= Button(self, text="...", height=1, width=1,command=self.select_vol)
		self.Volatility_button.place(x=353, y=185)
		
		#create encryption mode options
		self.encryption_mode_label = Label(self, text="Encryption Mode:")
		self.encryption_mode_label.place(x=15, y=215)
		self.encryption_mode = StringVar()
		#create radio buttons
		self.encryption_mode_aes = Radiobutton(self, text="AES", variable=self.encryption_mode, value="aes", command=self.update_options)
		self.encryption_mode_aes_twofish = Radiobutton(self, text="AES-Twofish", variable=self.encryption_mode, value="aes-twofish", command=self.update_options)
		self.encryption_mode_aes_twofish_serpent = Radiobutton(self, text="AES-Twofish-Serpent", variable=self.encryption_mode, value="aes-twofish-serpent", command=self.update_options)
		self.encryption_mode_serpent = Radiobutton(self, text="Serpent", variable=self.encryption_mode, value="serpent", command=self.update_options)
		self.encryption_mode_serpent_aes = Radiobutton(self, text="Serpent-AES", variable=self.encryption_mode, value="serpent-aes", command=self.update_options)
		self.encryption_mode_serpent_twofish_aes = Radiobutton(self, text="Serpent-Twofish-AES", variable=self.encryption_mode, value="serpent-twofish-aes", command=self.update_options)
		self.encryption_mode_twofish = Radiobutton(self, text="Twofish", variable=self.encryption_mode, value="twofish", command=self.update_options)
		self.encryption_mode_twofish_serpent = Radiobutton(self, text="Twofish-Serpent", variable=self.encryption_mode, value="twofish-serpent", command=self.update_options)
		self.encryption_mode.set("aes")
		#place radio buttons
		self.encryption_mode_aes.place(x=15, y=235)
		self.encryption_mode_serpent.place(x=15, y=255)
		self.encryption_mode_twofish.place(x=15, y=275)
		self.encryption_mode_aes_twofish.place(x=90, y=235)
		self.encryption_mode_serpent_aes.place(x=90, y=255)
		self.encryption_mode_twofish_serpent.place(x=90, y=275)
		self.encryption_mode_serpent_twofish_aes.place(x=205, y=235)
		self.encryption_mode_aes_twofish_serpent.place(x=205, y=255)
		
		#create hash mode options
		self.hash_mode_label = Label(self, text="Hash Function:")
		self.hash_mode_label.place(x=15, y=300)
		self.hash_mode = StringVar()
		#radio buttons
		self.hash_mode_ripemd = Radiobutton(self, text="RIPEMD", variable=self.hash_mode, value="ripemd", command=self.update_options)
		self.hash_mode_sha = Radiobutton(self, text="SHA-512", variable=self.hash_mode, value="sha-512", command=self.update_options)
		self.hash_mode_whirlpool = Radiobutton(self, text="Whirlpool", variable=self.hash_mode, value="whirlpool", command=self.update_options)
		self.hash_mode.set("ripemd")
		#place radio buttons
		self.hash_mode_ripemd.place(x=15, y=320)
		self.hash_mode_sha.place(x=90, y=320)
		self.hash_mode_whirlpool.place(x=164, y=320)
		
		#option checkboxes
		self.option_label = Label(self, text="Password options:")
		self.option_label.place(x=15, y=345)
		#veracrypt
		self.vera = IntVar()
		self.vera_checkbox = Checkbutton(self, text="VeraCrypt", variable=self.vera, command=self.update_options)
		self.vera_checkbox.place(x=15, y=365)
		#backup header
		self.backup = IntVar()
		self.backup_checkbox = Checkbutton(self, text="Backup Header", variable=self.backup, command=self.update_options)
		self.backup_checkbox.place(x=95, y=365)
		#hidden header
		self.hidden = IntVar()
		self.hidden_checkbox = Checkbutton(self, text="Hidden Header", variable=self.hidden, command=self.update_options)
		self.hidden_checkbox.place(x=200, y=365)
		#force
		self.force = IntVar()
		self.force_checkbox = Checkbutton(self, text="Force Decryption (requires offset and data size)", variable=self.force, command=self.update_options)
		self.force_checkbox.place(x=15, y=390)
		
		#offset options
		self.option_label = Label(self, text="Manual Offsets:")
		self.option_label.place(x=15, y=415)
		#start offset
		self.offset_label = Label(self, text="Offset:")
		self.offset_label.place(x=15, y=440)
		self.offset_entry = Entry(self)
		self.offset_entry.config(width=45)
		self.offset_entry.place(x=100, y=440)
		#data size
		self.offset_label = Label(self, text="Data Size:")
		self.offset_label.place(x=15, y=470)
		self.datasize_entry = Entry(self)
		self.datasize_entry.config(width=45)
		self.datasize_entry.place(x=100, y=470)
		
		#offset options
		self.option_label = Label(self, text="Output:")
		self.option_label.place(x=15, y=500)
		self.image_label = Label(self, text="Image Path:")
		self.image_label.place(x=15, y=520)
		self.image_entry = Entry(self)
		self.image_entry.config(width=41)
		self.image_entry.place(x=100, y=520)
		self.image_button= Button(self, text="...", height=1, width=1,command=self.select_image)
		self.image_button.place(x=353, y=520)
		
		#create start button
		self.go_button= Button(self, text="Decrypt!", command=self.image)
		self.go_button.place(x=15, y=550)

		#update the display
		self.update_options()
		
		

def main():  
	root = Tk()
	root.geometry("400x600")
	app = gui(root)
	root.resizable(width=False, height=False)
	root.mainloop()  


if __name__ == '__main__':
	main()  