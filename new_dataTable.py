import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()

# Create a new table named 'url_data_new'
cursor.execute("""
    CREATE TABLE IF NOT EXISTS url_data_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        label INTEGER NOT NULL  -- 1 for phishing, 0 for legitimate
    )
""")
conn.commit()
print("Table 'url_data_new' created successfully.")

# Insert sample data into 'url_data_new'
sample_data = [
    # Legitimate URLs (Label = 0)
    ("https://www.google.com", 0),
    ("https://www.apple.com", 0),
    ("https://www.microsoft.com", 0),
    ("https://www.amazon.com", 0),
    ("https://www.bankofamerica.com", 0),
    ("https://www.paypal.com", 0),
    ("https://www.facebook.com", 0),
    ("https://www.linkedin.com", 0),
    ("https://www.github.com", 0),
    ("https://www.zict.org", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.tesla.com", 0),
    ("https://www.adobe.com", 0),
    ("https://www.netflix.com", 0),
    ("https://www.dropbox.com", 0),
    ("https://www.nytimes.com", 0),
    ("https://www.ibm.com", 0),
    ("https://www.oracle.com", 0),
    ("https://www.salesforce.com", 0),
    ("https://www.intel.com", 0),

    # Phishing-Like URLs (Label = 1)
    ("http://secure-login-paypal.com", 1),
    ("http://apple-id-verification.com", 1),
    ("http://update-your-amazon-account.com", 1),
    ("http://google-verification-check.com", 1),
    ("http://microsoft-login-secure.com", 1),
    ("http://paypal-service-account.com", 1),
    ("http://facebook-security-alert.com", 1),
    ("http://linkedin-password-reset.com", 1),
    ("http://secure-bankofamerica-login.com", 1),
    ("http://zict-login-secure.com", 1),
    ("http://amazon-account-verify.com", 1),
    ("http://apple-support-id.com", 1),
    ("http://my-google-security.com", 1),
    ("http://login-microsoftsupport.com", 1),
    ("http://netflix-billing-secure.com", 1),
    ("http://update-dropbox-login.com", 1),
    ("http://security-nytimes.com", 1),
    ("http://update-oracle-account.com", 1),
    ("http://salesforce-security-alert.com", 1),
    ("http://intel-login-verification.com", 1),  # Missing comma was here
    ("https://facebook.marketplace-item382472.highshark.com.ng/", 1)  # Correctly added comma
]

# Insert the sample data into the table
cursor.executemany("INSERT INTO url_data_new (url, label) VALUES (?, ?)", sample_data)
conn.commit()
print("Sample data inserted successfully.")

# Close the database connection
conn.close()
