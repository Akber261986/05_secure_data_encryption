import os
import json
import hashlib

STORED_DATA = "data.json"

def load_data():
    if os.path.exists(STORED_DATA):
        with open(STORED_DATA, "r") as file:
            return json.load(file)
    else:
        return []
        
def save_data(data):
    with open(STORED_DATA, "w") as file:
        json.dump(data, file, indent=4)
        
def main():
#     my_key = "" #input("Enter the key: ")
#     my_value = "" #input("Enter Value: ")
#     data = {
#         my_key : my_value
#     }
#     loaded = load_data()
#     loaded.append(data)
#     save_data(loaded)
    loaded = load_data()
    for user in loaded:
        for key, value in user.items():
            print(value["encrypted_text"])
password = "admin123"
gh = hashlib.sha256(password.encode()).hexdigest()
print(gh)


if __name__ == "__main__":
    main()