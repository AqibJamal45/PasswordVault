import sqlite3, hashlib
from tkinter import *

#Database

with sqlite3.connect("passwordVault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterPassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")


#Inititate Window

window = Tk()
window.title("Password Vault")

def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()

    return hash

def firstScreen():
    window.geometry("250x150")
    
    label = Label(window, text="Create Master Password")
    label.config(anchor=CENTER)
    label.pack()
    
    text = Entry(window, width=20)
    text.pack()
    text.focus()
    
    label1 = Label(window, text="Retype Master Password")
    label1.pack()
    
    text1 = Entry(window, width=20)
    text1.pack()
    text1.focus()

    label2 = Label(window)
    label2.pack()

    def savePassword():
        if text.get() == text1.get():
            hashedPassword = hashPassword(text.get().encode("utf-8"))

            insert_password = """INSERT INTO masterPassword(password)
            VALUES(?) """
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()

            passwordVault()
        else:
            label2.config(text="Error! Passwords do not match")


    button = Button(window, text ="Save", command=savePassword)
    button.pack(pady=10)

def loginScreen():
    window.geometry("250x100")
    
    label = Label(window, text="Enter Master Password")
    label.config(anchor=CENTER)
    label.pack()
    
    text = Entry(window, width=20, show="*")
    text.pack()
    text.focus()

    label1 = Label(window)
    label1.pack()

    def getMasterPass():
        checkHashedPassword = hashPassword(text.get().encode("utf-8"))
        cursor.execute("SELECT * FROM masterPassword WHERE id = 1 AND password =?", [(checkHashedPassword)])
        print(checkHashedPassword)
        return cursor.fetchall()

    def checkPass():
        match = getMasterPass()

        print(match)

        if match:
            passwordVault()
        else:
            text.delete(0, "end")
            label1.config(text="Incorrect Entry")

    button = Button(window, text="Enter", command=checkPass)
    button.pack(pady=10)

def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("700x350")
    
    label = Label(window, text="Password Vault")
    label.config(anchor=CENTER)
    label.pack()

cursor.execute("SELECT * FROM masterPassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()

window.mainloop()