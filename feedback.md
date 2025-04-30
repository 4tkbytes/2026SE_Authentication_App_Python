# Feedback

### **Strengths**
1. **Use of `bcrypt` for Password Hashing**:
   - The code uses `bcrypt` for hashing passwords, which is a secure and industry-standard approach.

2. **Separation of Concerns**:
   - The code is modular, with functions like `login`, `register`, `change_password`, and `post_auth_menu` handling specific tasks.

3. **Use of `getpass` for Secure Input**:
   - The use of `getpass` ensures that passwords are not echoed to the terminal, improving security.

4. **File Handling**:
   - The code handles file operations for reading, writing, and updating user data effectively.

5. **Interactive Menus**:
   - The code provides clear and user-friendly menus for authentication and post-login actions.

---

### **Issues and Suggestions for Improvement**

#### 1. **Password Hashing is Not Fully Implemented**
   - The `encrypt` function is commented out, and passwords are stored in plain text in the file.

   **Fix**: Ensure passwords are hashed before storing them and verified during login.

   Example:
   ```python
   def encrypt(password: str):
       return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

   def login():
       username = input("Input your username: ")
       password = getpass.getpass("Input your password (No echo): ")
       search = search_file_k(database, username)
       try:
           if bcrypt.checkpw(password.encode('utf-8'), search[1].encode('utf-8')):
               print("Authenticated successfully!")
           else:
               print("Password is not correct, returning back to main menu")
               return "Incorrect Password!"
       except Exception:
           print("Username not found in database, returning back to main menu")
           return "Username not found in login"
       post_auth_menu()
       return ""
   ```

---

#### 2. **Hardcoded Salt**
   - The salt is hardcoded (`salt = b"$2b$12$ieYNkQp8QumgedUo30nuPO"`), which reduces the security of the hashing process.

   **Fix**: Use `bcrypt.gensalt()` to generate a unique salt for each password.

   Example:
   ```python
   def encrypt(password: str):
       return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
   ```

---

#### 3. **Error Handling is Inconsistent**
   - Some functions, like `search_file_k`, print errors directly, while others return error strings. This inconsistency can make debugging harder.

   **Fix**: Standardize error handling by raising exceptions or returning error messages consistently.

---

#### 4. **Inefficient File Search**
   - The `search_file_k` function reads the file line by line for every search, which can be slow for large files.

   **Fix**: Load the file into memory once and use a dictionary for faster lookups.

   Example:
   ```python
   def load_users():
       users = {}
       try:
           with open(database, 'r') as file:
               for line in file:
                   username, password = line.strip().split(',')
                   users[username] = password
       except FileNotFoundError:
           pass
       return users
   ```

---

#### 5. **No Input Validation for Usernames**
   - The code does not validate usernames, which could lead to issues like duplicate usernames with different cases (e.g., `User` and `user`).

   **Fix**: Normalize usernames (e.g., convert to lowercase) and validate them.

   Example:
   ```python
   username = input("Enter your username: ").strip().lower()
   ```

---

#### 6. **No File Locking**
   - Concurrent access to the `database` file could lead to data corruption.

   **Fix**: Use file locking mechanisms (e.g., `fcntl` or `portalocker`) to prevent concurrent writes.

---

#### 7. **Password Change Logic is Flawed**
   - The `change_password` function verifies the old password by searching for it directly in the file, which is insecure and incorrect.

   **Fix**: Verify the old password using the username and hashed password.

   Example:
   ```python
   def change_password(username):
       old_password = getpass.getpass("Input your old password for verification (no echo): ")
       users = load_users()
       if username in users and bcrypt.checkpw(old_password.encode('utf-8'), users[username].encode('utf-8')):
           print("Password verified!")
       else:
           print("Old password is incorrect.")
           return
       while True:
           new_password = getpass.getpass("Input your new password (no echo): ")
           if len(new_password) < 4:
               print("Password is less than 4 characters")
               continue
           confirm_password = getpass.getpass("Confirm your new password (no echo): ")
           if new_password == confirm_password:
               users[username] = encrypt(new_password)
               save_users(users)
               print("Password changed successfully!")
               return
           else:
               print("Passwords do not match. Try again.")
   ```

---

#### 8. **No Unit Tests**
   - The code lacks unit tests to verify the functionality of critical components like `login`, `register`, and `change_password`.

   **Fix**: Add unit tests using a framework like `unittest` or `pytest`.