import tkinter as tk
from tkinter import ttk, messagebox
import json
import bcrypt
import random
import string

class ProfileFrame(ttk.Frame):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        ttk.Label(self, text="Welcome to your Profile!").pack(pady=10)
        ttk.Button(self, text="Logout", command=self.logout).pack()

    def logout(self):
        notebook.select(0)  
        notebook.select(1) 
        notebook.hide(2)  

def generate_captcha():
    captcha_characters = string.ascii_letters + string.digits
    captcha = ''.join(random.choice(captcha_characters) for _ in range(6))
    print(captcha)
    return captcha

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def save_user(username, password):
    try:
        with open('users.json', 'r') as file:
            data = file.read()
            if not data:
                users = {}
            else:
                users = json.loads(data)
    except FileNotFoundError:
        users = {}

    hashed_password = hash_password(password)

    users[username] = {'password': hashed_password.decode('utf-8')}

    with open('users.json', 'w') as file:
        json.dump(users, file)

def check_credentials(username, password):
    with open('users.json', 'r') as file:
        users = json.load(file)

    if username in users:
        hashed_password = users[username]['password'].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            return True
    return False

def sign_up():
    username = sign_up_username_entry.get()
    password = sign_up_password_entry.get()
    reentered_password = sign_up_reenter_password_entry.get()
    entered_captcha = sign_up_captcha_entry.get()

    if not username or not password or not reentered_password or not entered_captcha:
        messagebox.showerror("Error", "All fields are required.")
        return

    if password != reentered_password:
        messagebox.showerror("Error", "Passwords do not match.")
        return

    if entered_captcha.lower() != captcha.lower():
        messagebox.showerror("Error", "Incorrect CAPTCHA.")
        return

    save_user(username, password)
    messagebox.showinfo("Success", "Account created successfully!")

    notebook.hide(0)  
    notebook.hide(1)  
    notebook.select(2)  

def refresh_captcha():
    global captcha
    captcha = generate_captcha()
    print(captcha)
    captcha_label.config(text=captcha)

def login():
    username = login_username_entry.get()
    password = login_password_entry.get()

    if not username or not password:
        messagebox.showerror("Error", "Username and password are required.")
        return

    if check_credentials(username, password):
        messagebox.showinfo("Success", "Login successful!")

        notebook.hide(0)  
        notebook.hide(1) 
        notebook.select(2)  

    else:
        messagebox.showerror("Error", "Invalid username or password.")

def toggle_password(entry, var):
    if var.get():
        entry['show'] = ''
    else:
        entry['show'] = '*'

# GUI setup
root = tk.Tk()
root.title("Login and Sign Up")

notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

sign_up_frame = ttk.Frame(notebook)
notebook.add(sign_up_frame, text="Sign Up")

ttk.Label(sign_up_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
sign_up_username_entry = ttk.Entry(sign_up_frame)
sign_up_username_entry.grid(row=0, column=1, padx=5, pady=5)

ttk.Label(sign_up_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
sign_up_password_entry = ttk.Entry(sign_up_frame, show="*")
sign_up_password_entry.grid(row=1, column=1, padx=5, pady=5)

ttk.Label(sign_up_frame, text="Re-enter Password:").grid(row=2, column=0, padx=5, pady=5)
sign_up_reenter_password_entry = ttk.Entry(sign_up_frame, show="*")
sign_up_reenter_password_entry.grid(row=2, column=1, padx=5, pady=5)

show_password_var_signup = tk.BooleanVar()
show_password_checkbox_signup = ttk.Checkbutton(sign_up_frame, text="Show Password", variable=show_password_var_signup, command=lambda: toggle_password(sign_up_password_entry , show_password_var_signup) or toggle_password(sign_up_reenter_password_entry , show_password_var_signup))
show_password_checkbox_signup.grid(row=3, column=0, columnspan=2, pady=5)

captcha = generate_captcha()
ttk.Label(sign_up_frame, text="Captcha:").grid(row=4, column=0, padx=2, pady=3)
captcha_label = ttk.Label(sign_up_frame, text=captcha) 
captcha_label.grid(row=4, column=1, padx=2, pady=3)

ttk.Label(sign_up_frame, text="Enter Captcha:").grid(row=5, column=0, padx=5, pady=3)
sign_up_captcha_entry = ttk.Entry(sign_up_frame)
sign_up_captcha_entry.grid(row=5, column=1, padx=5, pady=5)

ttk.Button(sign_up_frame, text="Sign Up", command=sign_up).grid(row=6, column=0, columnspan=2, pady=10)
ttk.Button(sign_up_frame, text="Re-Captcha", command=refresh_captcha).grid(row=7, column=0, columnspan=2, pady=5)

login_frame = ttk.Frame(notebook)
notebook.add(login_frame, text="Login")

ttk.Label(login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
login_username_entry = ttk.Entry(login_frame)
login_username_entry.grid(row=0, column=1, padx=5, pady=5)

ttk.Label(login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
login_password_entry = ttk.Entry(login_frame, show="*")
login_password_entry.grid(row=1, column=1, padx=5, pady=5)

show_password_var_login = tk.BooleanVar()
show_password_checkbox_login = ttk.Checkbutton(login_frame, text="Show Password", variable=show_password_var_login, command=lambda: toggle_password(login_password_entry, show_password_var_login))
show_password_checkbox_login.grid(row=2, column=0, columnspan=2, pady=5)

ttk.Button(login_frame, text="Login", command=login).grid(row=3, column=0, columnspan=2, pady=10)

profile_frame = ProfileFrame(notebook)
notebook.add(profile_frame, text="Profile")

notebook.hide(2)

root.mainloop()
