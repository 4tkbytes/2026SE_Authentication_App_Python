import sys
import getpass
import bcrypt

database = "pass.csv"

def quit():
    print("Goodbye, see you later :)")
    sys.exit(0)

def encrypt(password: str):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def compare(input_password:str, hashed_password) -> bool:
    if isinstance(hashed_password, list) and len(hashed_password) > 1:
        # Extract the hashed password from the list (should be the second element)
        hashed_str = hashed_password[1]
        # Convert both to bytes for comparing
        return bcrypt.checkpw(input_password.encode('utf-8'), hashed_str.encode('utf-8'))
    elif isinstance(hashed_password, str):
        # If it's already a string, encode both
        return bcrypt.checkpw(input_password.encode('utf-8'), hashed_password.encode('utf-8'))
    else:
        # If it's already bytes, use as-is for the hashed password
        return bcrypt.checkpw(input_password.encode('utf-8'), hashed_password)

def write(username:str, password:str):
    # check if user already exists
    with open(database, 'r') as file:
        for line in file:
            if username in line:
                print("User already exists, therefore unable to create new user. Returning")
                return "User already exists"
    
    # append item to file
    with open(database, "a") as file:
        file.write(f"{username},{encrypt(password)}\n")
        # file.write(f"{username},{password}\n")
    return ""

def search_file_k(file_path:str, keyword:str):
    # searches file using path and keyword, then returns the key and value
    with open(file_path, 'r') as file:
        for line in file:
            if keyword in line:
                return line.strip().split(',')
        print("Keyword does not exist")
        return

def change_item_in_file_k(file_path:str, keyword:str, new_item:str):
    # Open old password file
    segregated = ""
    list_of_users = []
    with open(file_path) as old_file:
        for line in old_file:
            # check if keyword is in line
            if keyword in line:
                segregated = line.strip().split(",")[0]
            else:
                # else append to list
                list_of_users.append(line)
    
    # create a new file under same name
    with open(file_path, "w") as file:
        for item in list_of_users:
            file.write(item)
        file.write(f"{segregated},{new_item}")
    
    print("Item successfully changed!")
    return ""

def change_password():
    username = input("Input your username: ")
    old_password = getpass.getpass("Input your old password for verification (no echo): ")
    
    user_record = search_file_k(database, username)
    
    if user_record is None:
        print("Username not found, returning back to main menu...")
        return "Username not found"
    
    try:
        if compare(old_password, user_record):
            print("Password verified!")
        else:
            print("Old password is wrong, returning back to main menu...")
            return "Old password is not correct"
    except Exception as e:
        print(f"Error verifying password: {e}")
        return "Password verification error"

    while True:
        tmp = getpass.getpass("Input your new password (no echo): ")
        if len(tmp) < 4:
            print("Password is less than 4 characters")
            continue
        new_password = getpass.getpass("Confirm your new password (no echo): ")
        if new_password == tmp:
            encrypted_password = encrypt(new_password)
            return change_item_in_file_k(database, username, encrypted_password)
        else:
            print("Password is not the same, try again...")
            continue

def post_auth_menu():
    while True:
        err_string = ""
        print(f"""
        ===========================
            Example Auth Client
        ===========================
            Choose your option
            ---
            [1] - Change Password

            [q] - Logout
        ===========================
        {"Error: " if not len(err_string) == 0 else ""}{err_string if not len(err_string) == 0 else "    No errors reported"}
        ===========================
            """)
        choice = input("Choice: ").lower()
        match choice:
            case "1":
                err_string = change_password()
                continue
            case "q":
                print("Successfully logged out!")
                quit()
            case _:
                print("Choice does not exist")
                continue

def login():
    username = input("Input your username: ")
    password = getpass.getpass("Input your password (No echo): ")
    
    # Try to find the user in the database
    search = search_file_k(database, username)
    
    # Check if user was found
    if search is None:
        print("Username not found in database, returning back to main menu")
        return "Username not found in login"
    
    # Check if password matches using our compare function
    try:
        if compare(password, search):
            print("Authenticated successfully!")
            post_auth_menu()
            return ""
        else:
            print("Password is not correct, returning back to main menu")
            return "Incorrect Password!"
    except Exception as e:
        print(f"Authentication error: {e}")
        return f"Auth error"

def register():
    # check if file exists, if not create a new one
    try:
        file = open(database)
        file.close()
    except:
        print("File doesn't exist, initialising new pass file")
        file = open(database, "w")
        file.close()
    
    # ask user for their username and password
    username = input("Enter your username: ")
    while True:
        password = getpass.getpass("Enter your password (No password echo for security purposes): ", )
        if len(password) < 4:
            print("Password must be greater than 4 characters, try again...")
            continue
        reconfirm_password = getpass.getpass("Reconfirm your password: ")
        if password == reconfirm_password:
            print("Password confirmed!")
            break
        else:
            print("Password not the same, please re-enter it again")
            continue
    
    # write the content to a file
    errString = write(username, password)
    if len(errString) != 0:
        print("Error creating new user")
        return errString
    print("Successfully created new user, returning back to main menu!")
    return ""

# literally just checks the user count by enumerating the line count in db
def check_user_count():
    try:
        line_count = 0
        with open(database) as file:
            for _ in file:
                line_count+=1
        return line_count
    except:
        return 0

def main():
    err_string = ""

    while True:
        # create main menu
        user_count = check_user_count()
        print(f"""    ===========================
        Example Auth Client
    ===========================
        Choose your option
        ---
        [1] - Login
        [2] - Register
        
        [q] - Quit
    ===========================
    Stats: {user_count} users on platform
    {"Error: " if not len(err_string) == 0 else ""}{err_string if not len(err_string) == 0 else "    No errors reported"}
    ===========================
        """)
        choice = input("Choice: ").lower()

        # match up the choice
        match choice:
            case 'q':
                quit()
                break
            case '1':
                err_string = login()
            case '2':
                err_string = register()
            case _:
                print("Unable to determine choice, returning back to main menu")
                err_string = "Choose correctly >:("
        continue

if __name__ == '__main__':
    main()