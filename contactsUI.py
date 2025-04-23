import tkinter as tk

m = tk.Tk()
m.title("Encrypted Messenger - Contacts")
# m.geometry("300x400")

#contacts list
tk.Label(m, text="Contacts", font=("Helvetica", 16)).pack(pady=10)
contacts = ["Alice", "Bob", "Charlie", "David"] #sample adjust later with contacts from server
#display all contacts as clickable item
for contact in contacts:
    contact_button = tk.Button(m, text=contact, command=lambda c=contact: print(f"Clicked on {c}"))
    contact_button.pack(pady=5)



m.mainloop()