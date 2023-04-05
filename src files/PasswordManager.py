import json
import os
import random
import re
import secrets
import string
from tkinter import messagebox
import customtkinter
import zxcvbn
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from tkinter import filedialog
from customtkinter.windows.widgets.font import Font


customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("green")


class PasswordManagerApp(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # configure window
        self.title("Password Manager")
        self.geometry(f"{880}x{420}")

        # configure grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # Main Buttons for Checking and Generating
        self.button_frame1 = customtkinter.CTkFrame(self)
        self.button_frame1.grid(row=0, column=1, padx=5, pady=10, sticky="ns")
        self.main_button_1 = customtkinter.CTkButton(master=self.button_frame1, fg_color="transparent", border_width=2,
                                                     text_color=("gray10", "#DCE4EE"), text='Generate Random Password',
                                                     command=self.password_generator)
        self.main_button_1.grid(row=0, column=1, padx=5, pady=10, ipady=2, sticky="n")
        self.main_button_2 = customtkinter.CTkButton(master=self.button_frame1, fg_color="transparent", border_width=2,
                                                     text_color=("gray10", "#DCE4EE"), text='Generate Random Words',
                                                     command=self.password_gen_withwords)
        self.main_button_2.grid(row=1, column=1, padx=5, pady=10, sticky="n")
        self.main_button_3 = customtkinter.CTkButton(master=self.button_frame1, fg_color="transparent", border_width=2,
                                                     text_color=("gray10", "#DCE4EE"), text='Check',
                                                     command=self.password_checker)
        self.main_button_3.grid(row=2, column=1, padx=5, pady=10, sticky="n")

        # Main Buttons for Total Save, Encrypt and Decrypt
        self.button_frame2 = customtkinter.CTkFrame(self)
        self.button_frame2.grid(row=0, column=0, padx=5, pady=10, sticky="ns")
        self.label_button_group = customtkinter.CTkLabel(master=self.button_frame2, text="Encrypt / Decrypt File")
        self.label_button_group.grid(row=0, column=0, padx=10, pady=10, sticky="ns")
        self.main_button_4 = customtkinter.CTkButton(master=self.button_frame2, fg_color="transparent", border_width=2,
                                                     text_color=("gray10", "#DCE4EE"), text='Decrypt',
                                                     command=self.decrypt_file)
        self.main_button_4.grid(row=1, column=0, padx=5, pady=10, sticky="n")
        self.main_button_5 = customtkinter.CTkButton(master=self.button_frame2, fg_color="transparent", border_width=2,
                                                     text_color=("gray10", "#DCE4EE"), text='Save and Encrypt',
                                                     command=self.save_file)
        self.main_button_5.grid(row=2, column=0, padx=5, pady=10, sticky="n")

        # Textbox for Generating Password and Random Words
        self.textbox_frame = customtkinter.CTkFrame(self)
        self.textbox_frame.grid(row=0, column=2, padx=5, pady=10, sticky="ns")
        self.textbox_1 = customtkinter.CTkTextbox(self.textbox_frame, height=1, width=200)
        self.textbox_1.grid(row=0, column=2, padx=5, pady=10, sticky="we")
        self.textbox_2 = customtkinter.CTkTextbox(self.textbox_frame, height=1, width=200)
        self.textbox_2.grid(row=1, column=2, padx=5, pady=10, sticky="we")

        # Entry for User Input Password
        self.entry = customtkinter.CTkEntry(self.textbox_frame, height=1, width=200,
                                            placeholder_text="Enter Custom Password")
        self.entry.grid(row=2, column=2, padx=10, pady=12, sticky="n")

        # Entry for Username
        self.entry2 = customtkinter.CTkEntry(self.textbox_frame, height=1, width=200,
                                             placeholder_text="Enter Username")
        self.entry2.grid(row=3, column=2, padx=10, pady=12, sticky="n")

        # Entry for Website
        self.entry3 = customtkinter.CTkEntry(self.textbox_frame, height=1, width=200,
                                             placeholder_text="Enter Website")
        self.entry3.grid(row=4, column=2, padx=10, pady=12, sticky="n")

        # Textbox with set value
        self.textbox_3 = customtkinter.CTkTextbox(self.button_frame1, width=200)
        self.textbox_3.grid(row=3, column=1, padx=5, pady=10, sticky="N")
        self.textbox_3.insert("0.0", "Note:\n\n" + "The system will only check for these parameters: \n\n" +
                              "Minimum password length: 8   characters \n" + "Maximum password length: 64 characters \n" +
                              "Password must contain one    special character, such as ""[!@#$%^&*(),_.?\":{}|<>] \n" +
                              "Password must have at least one upper-case and lower-case letter \n\n" +
                              "Password strength goes from 0 - 4; 0 being the weakest, 4 being the strongest"
                              "If password strength is <=2, its recommend that the password needs to change, "
                              "if its >=3,"
                              + " the password can be useable.")

        # Radio Buttons for selecting what to save
        self.radiobutton_frame = customtkinter.CTkFrame(self)
        self.radiobutton_frame.grid(row=0, column=3, padx=12, pady=10, sticky="ns")
        self.radio_var = customtkinter.IntVar(value=0)
        self.label_radio_group = customtkinter.CTkLabel(master=self.radiobutton_frame, text="Select Password to Save")
        self.label_radio_group.grid(row=0, rowspan=1, column=3, padx=10, pady=10, sticky="")
        self.radio_button_1 = customtkinter.CTkRadioButton(master=self.radiobutton_frame, variable=self.radio_var,
                                                           value=0, text="Random Password")
        self.radio_button_1.grid(row=1, column=3, pady=10, padx=20, sticky="we")
        self.radio_button_2 = customtkinter.CTkRadioButton(master=self.radiobutton_frame, variable=self.radio_var,
                                                           value=1, text="Random Password with words")
        self.radio_button_2.grid(row=2, column=3, pady=10, padx=20, sticky="we")
        self.radio_button_3 = customtkinter.CTkRadioButton(master=self.radiobutton_frame, variable=self.radio_var,
                                                           value=2, text="User Password")
        self.radio_button_3.grid(row=3, column=3, pady=10, padx=20, sticky="we")

    def password_generator(self):
        alphabet = string.ascii_letters + string.digits + '-_!@#$%^&*()'
        password = ''.join(secrets.choice(alphabet) for i in range(12))
        self.textbox_1.delete("0.0", "12.0")
        self.textbox_1.insert("0.0", password)

    def password_gen_withwords(self):
        file = open("wordlist.10000.txt", "r")
        words = file.read().splitlines()
        random_words = random.sample(words, 3)
        self.textbox_2.delete("0.0", "64.0")
        self.textbox_2.insert("0.0", random_words)

    def password_checker(self):
        user_input = self.entry.get()
        result = zxcvbn.zxcvbn(user_input)
        errors = []

        # Check for length
        if len(user_input) < 8:
            errors.append("Password is too short.")
        if len(user_input) > 64:
            errors.append("Password is too long.")

        # Check for uppercase letters
        if not re.search(r"[A-Z]", user_input):
            errors.append("Password should contain at least one uppercase letter.")

        # Check for lowercase letters
        if not re.search(r"[a-z]", user_input):
            errors.append("Password should contain at least one lowercase letter.")

        # Check for digits
        if not re.search(r"\d", user_input):
            errors.append("Password should contain at least one digit.")

        # Check for special characters
        if not re.search(r"[!@#$%^&*(),_.?\":{}|<>]", user_input):
            errors.append("Password should contain at least one special character, Example:[!@#$%^&*(),_.?\":{}|<>]")

        # Output errors
        if errors:
            messagebox.showerror("Error", "\n".join(errors))
        else:
            messagebox.showinfo("Info", f"Password strength: {result['score']}/4")
            messagebox.showinfo("Info", "Password fits parameters.")

    # Save and encrypts inputs to a file without overriding
    def save_file(self):
        filename = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[("JSON Files", "*.json")],
                                                confirmoverwrite=False)

        # data
        generate_password = self.textbox_1.get("0.0", "64.0")
        generate_words = self.textbox_2.get("0.0", "64.0")
        user_password = self.entry.get()
        username = self.entry2.get(),
        website = self.entry3.get()
        radio_val = self.radio_var.get()

        data = {
            "generate_password": generate_password,
            "generate_words": generate_words,
            "user_password": user_password,
            "username": username,
            "website": website,
            "radio_val": radio_val
        }

        if filename:
            if radio_val == 0:
                data = {"Username": username, "Pass": generate_password, "Site": website}
            elif radio_val == 1:
                data = {"Username": username, "Pass": generate_words, "Site": website}
            elif radio_val == 2:
                data = {"Username": username, "Pass": user_password, "Site": website}

            # Convert dictionary to JSON
            json_data = json.dumps(data)

            # Generate random key and initialization vector
            key = get_random_bytes(32)
            iv = get_random_bytes(16)

            # Encrypt data with AES-256-CBC
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(self.pad(json_data.encode('utf-8')))

            # Write encrypted data to file
            with open(filename, 'wb') as f_out:
                f_out.write(iv + ciphertext)

            # Save key to a separate file
            with open(os.path.splitext(filename)[0] + ".key", "wb") as f_key:
                f_key.write(key)

            f_out.close()
            f_key.close()

            messagebox.showinfo("Success!", "File saved and encrypted successfully!")

    def decrypt_file(self):
        filename = filedialog.askopenfilename(defaultextension='.json', filetypes=[("JSON Files", "*.json")])
        keyfile = os.path.splitext(filename)[0] + ".key"

        # Read key from file
        with open(keyfile, "rb") as f_key:
            key = f_key.read()

        with open(filename, 'rb') as f_in:
            # read data from file
            data = f_in.read()
            # get initialization vector and encrypted data
            iv = data[:16]
            encrypted_data = data[16:]
            # generate cipher object
            cipher = AES.new(key, AES.MODE_CBC, iv)
            # decrypt data
            decrypted_data = self.unpad(cipher.decrypt(encrypted_data))

        # Load decrypted data from JSON
        decrypted_data = json.loads(decrypted_data)

        # Write decrypted data to file
        with open(os.path.splitext(filename)[0] + ".txt", 'a') as f_out:
            f_out.write(
                "Username: {0}\n"  "Pass: {1}\n"    "Site: {2}\n\n".format(
                    str(decrypted_data['Username']).strip("'[]'"),
                    decrypted_data['Pass'],
                    decrypted_data['Site']))

        f_out.close()
        f_key.close()

        messagebox.showinfo("Success!", "File decrypted successfully!")

    # function to pad data to match AES block size
    def pad(self, data):
        block_size = AES.block_size
        padding_size = block_size - len(data) % block_size
        padding = bytes([padding_size]) * padding_size
        return data + padding

    # function to unpad data
    def unpad(self, data):
        padding_size = data[-1]
        return data[:-padding_size]


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
