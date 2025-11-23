from passlib.hash import pbkdf2_sha256

class PasswordManager:
    """
    A simple password manager using passlib for secure password hashing and verification.
    """
    
    @staticmethod
    def hash_password(password):
        """
        Hash a password using PBKDF2-SHA256 algorithm.
        
        Args:
            password (str): The plain text password to hash
            
        Returns:
            str: The hashed password as a string
        """
        hashed = pbkdf2_sha256.hash(password)
        return hashed
    
    @staticmethod
    def verify_password(password, hashed_password):
        """
        Verify a password against its hash.
        
        Args:
            password (str): The plain text password to verify
            hashed_password (str): The hashed password to check against
            
        Returns:
            bool: True if password matches, False otherwise
        """
        return pbkdf2_sha256.verify(password, hashed_password)


# Example usage
if __name__ == "__main__":
    pm = PasswordManager()
    
    # Example 1: Hash a password
    print("=== Password Hashing Demo ===\n")
    plain_password = "MySecurePassword123!"
    print(f"Original password: {plain_password}")
    
    # Hash the password
    hashed = pm.hash_password(plain_password)
    print(f"Hashed password: {hashed}")
    print(f"Hash type: {type(hashed)}") # It's a string
    print(f"Hash length: {len(hashed)} characters\n")
    
    # Example 2: Verify correct password
    print("=== Authentication Demo ===\n")
    test_password = "MySecurePassword123!"
    is_valid = pm.verify_password(test_password, hashed)
    print(f"Testing password: '{test_password}'")
    print(f"Authentication result: {'✓ SUCCESS' if is_valid else '✗ FAILED'}\n")
    
    # Example 3: Verify incorrect password
    wrong_password = "WrongPassword"
    is_valid = pm.verify_password(wrong_password, hashed)
    print(f"Testing password: '{wrong_password}'")
    print(f"Authentication result: {'✓ SUCCESS' if is_valid else '✗ FAILED'}\n")
    
    # Example 4: Multiple users
    print("=== Multiple Users Example ===\n")
    users = {
        "alice": pm.hash_password("alice_pass_2024"),
        "bob": pm.hash_password("bob_secure_pwd"),
        "charlie": pm.hash_password("charlie123!")
    }
    
    print("Stored user hashes:")
    for username, hash_value in users.items():
        print(f"{username}: {hash_value[:50]}...")
    
    # Authenticate a user
    print("\nAuthentication attempts:")
    login_attempts = [
        ("alice", "alice_pass_2024"), # Correct
        ("bob", "wrong_password"), # Incorrect
        ("charlie", "charlie123!") # Correct
    ]
    
    for username, password in login_attempts:
        if username in users:
            result = pm.verify_password(password, users[username])
            status = "✓ Authenticated" if result else "✗ Failed"
            print(f"{username} with password '{password}': {status}")# password-hashing-and-authentication
