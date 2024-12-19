"""

Name: Gokhan Unal
Date: <10/22/2024><10/23/2024> - UPDATE DATE: <11/16/2024>
Assignment: #12 FLASK - Encrypt Data in DB
Due Date: 11/17/2024
I also printed out the unencrypted user info to make sure
the Mentor can see the username password combos.

"""

import sqlite3
from cryptography.fernet import Fernet

# get the encryption key
with open('key.key', 'rb') as key_file:
    key = key_file.read()
# set the cipher
cipher = Fernet(key)


def encrypt(user_information) -> cipher:
    """
    :param user_information:
    :return: encrypted user information
    Date 11/16/2024
    """
    return cipher.encrypt(user_information.encode('utf-8'))


def decrypt(user_information) -> cipher:
    """
    :param user_information:
    :return: decrypted user information
    Date: 11/16/2024
    """
    return cipher.decrypt(user_information).decode('utf-8')


def create_tables():
    """
    Create tables - DDL part
    :return: nothing
    """
    # create a connection to sqlite3 db
    con = sqlite3.connect('baking_contest.db')
    # create the cursor object
    cursor = con.cursor()
    print("Connection established")
    # drop table statement - first bullet point
    cursor.execute("DROP TABLE IF EXISTS BakingContestPeople")
    print("BakingContest table dropped")
    # create the table with according attributes on canvas
    cursor.execute("""
    CREATE TABLE BakingContestPeople (
        UserID INTEGER PRIMARY KEY,
        Name TEXT NOT NULL,
        Age INTEGER,
        PhNum TEXT NOT NULL,
        SecurityLevel TEXT NOT NULL,
        LoginPassword TEXT NOT NULL)""")
    print("BakingContestPeople table created")

    # commit the table
    con.commit()
    con.close()
    print("Connection closed")


def insert_data_into_tables():
    """
    Inserts data into tables - DML PART
    Instead of directly inserting into SQLite3 table
    I create a list of tuples, encrypt the user info
    then I insert them into the SQLite3 table
    """
    # create the connection and the cursor
    con = sqlite3.connect('baking_contest.db')
    cursor = con.cursor()
    print("Connection re-established")
    # insert each tuple(user) into a list
    user_information = [
        (1, 'CartmanBrah', 30, '123-456-7890', '3', 'manBEARpig'),
        (2, 'JohnWick', 40, '123-555-5850', '3', 'parabelluM'),
        (3, 'kamalah', 20, '123-456-8888', '1', 'dumbKamalah'),
        (4, 'satanYahoo', 30, '123-666-6666', '1', 'f@pig'),
        (5, 'BabaYaga', 100, '123-555-5850', '2', 'forPeace'),
        (6, 'CupidYe', 20, '123-555-3434', '3', 'theheheheHEhehe')
    ]
    # encrypt user information, then insert
    for row in user_information:
        encrypted_data = (row[0], encrypt(row[1]), row[2], encrypt(row[3]), row[4], encrypt(row[5]))
        cursor.execute("INSERT INTO BakingContestPeople (UserID, Name, Age, PhNum, SecurityLevel, LoginPassword) "
                       "VALUES (?, ?, ?, ?, ?, ?)", encrypted_data)

    # commit the changes and close the connection
    con.commit()

    # select all rows per instructions and fetch
    cursor.execute("SELECT * FROM BakingContestPeople")
    rows = cursor.fetchall()
    print('--Encrypted data in BakingContestPeople Table--')
    for row in rows:
        print(row)

    # print the decrypted table to help the mentor verify
    print("\n--Decrypted data from BakingContestPeople Table--")
    for row in rows:
        decrypted_data = (row[0], decrypt(row[1]), row[2], decrypt(row[3]), row[4], decrypt(row[5]))
        print(decrypted_data)

    con.close()
    print("Connection closed")


# name block
if __name__ == '__main__':
    # Generate the key and save it to a file
    create_tables()
    insert_data_into_tables()

