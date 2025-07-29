import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import base64
import os

#Database

with sqlite3.connect("passwordVault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterPassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

#Create PopUp
def popUp(text):
    answer = simpledialog.askstring("input string", text, parent=window)
    return answer


#Inititate Window

window = Tk()
window.title("Password Vault")

def hashPassword(input):
    hash = hashlib.sha256(input)
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
        return cursor.fetchall()

    def checkPass():
        match = getMasterPass()

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

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        website = popUp(text1)
        username = popUp(text2)
        password = popUp(text3)

        insert_fields = """INSERT INTO vault(website, username, password)
        VALUES(?,?,?)"""

        cursor.execute(insert_fields,(website, username, password))
        db.commit()

        passwordVault()
    
    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        passwordVault()

    window.geometry("700x350")
    
    label = Label(window, text="Password Vault")
    label.grid(column=1)

    button = Button(window, text="Add", command=addEntry)
    button.grid(column=1,pady=10)
    
    label = Label(window, text="Website")
    label.grid(row=2, column=0, padx=80)
    label = Label(window, text="Username")
    label.grid(row=2, column=1, padx=80)
    label = Label(window, text="Password")
    label.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
    if(cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            label1 = Label(window, text=(array[i][1]), font=("Helvetica", 12))
            label1.grid(column=0, row=i+3)
            label1 = Label(window, text=(array[i][2]), font=("Helvetica", 12))
            label1.grid(column=1, row=i+3)
            label1 = Label(window, text=(array[i][3]), font=("Helvetica", 12))
            label1.grid(column=2, row=i+3)

            button = Button(window, text="Delete", command=partial(removeEntry, array[i][0]))
            button.grid(column=3, row=i+3, pady=10)

            i = i+1

            cursor.execute("SELECT * FROM vault")
            if (len(cursor.fetchall()) <= 1):
                break

cursor.execute("SELECT * FROM masterPassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()

window.mainloop()