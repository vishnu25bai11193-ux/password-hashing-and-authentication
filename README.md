Password hashing and authentication 
My project is all about hashing passwords then authenticating them to convert them into a string 
Password hashing is the process of converting a user's password into a unique, fixed-length string of characters called a hash using a one-way function. This is a crucial authentication feature because it allows a system to verify a user's login without storing the actual password in plain text, making it much safer if the database is breached. When a user logs in, the system hashes the entered password and compares the resulting hash with the one stored in the database; if they match, the user is authenticated 
I have used the library passlib
pip install passlib 
tried to run the code in vs code by having extension 
Password Hashing Instructions
Never store plain-text passwords. Only store the hashed passwords.
Use strong, slow hashing algorithms designed for passwords. Recommended algorithms include:
Argon2id (winner of the Password Hashing Competition)
Scrypt
Bcrypt (widely used and secure for legacy systems)
Always use a unique, cryptographically secure random salt for each password before hashing. The salt should have at least 120 bits of entropy and be stored in the database alongside the hash. The salt ensures that identical passwords result in different hashes, protecting against rainbow table attacks.
Do not "roll your own" hashing mechanism. Use well-vetted, peer-reviewed libraries and frameworks for your specific programming language (e.g., bcrypt for Node.js, password_hash() in PHP, libraries in ASP.NET Core Identity, Django, Spring Security).
Ensure sufficient database field length to store the full output of modern hashing algorithms, as the length can vary or change over time.
Consider "peppering" by using a secret key (pepper) that is stored in a separate, secure location, not the database. This adds another layer of security, but only if the algorithm supports it. 
