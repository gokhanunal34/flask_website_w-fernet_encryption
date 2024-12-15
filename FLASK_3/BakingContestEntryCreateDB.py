"""

Name: Gokhan Unal
Date: <10/22/2024><10/23/2024> - UPDATE DATE: <11/16/2024>
Assignment: #12 FLASK - Encrypt Data in DB
Due Date: 11/17/2024

"""

import sqlite3


def contest_entry_create():
    """ Creates the database tables for the contest entry """
    # Connect to the database and create the cursor
    con = sqlite3.connect('baking_contest.db')
    cursor = con.cursor()
    print("Connection established")
    # table creation
    cursor.execute("DROP TABLE IF EXISTS BakingContestEntry")
    print("BakingContestEntry table dropped.")
    cursor.execute("""CREATE TABLE BakingContestEntry(
                    EntryId INTEGER PRIMARY KEY,
                    UserID INTEGER,
                    NameOfBakingItem TEXT NOT NULL,
                    NumExcellentVotes INTEGER,
                    NumOkVotes INTEGER,
                    NumBadVotes INTEGER,
                    FOREIGN KEY (UserID) REFERENCES BakingContestPeople(UserID))""")
    print("BakingContestEntry table created.")

    # select all rows per instructions
    cursor.execute("SELECT * FROM BakingContestEntry")
    rows: list = cursor.fetchall()
    # print the rows
    for row in rows:
        print(row)

    # commit changes and close connection
    con.commit()
    con.close()
    print("Connection closed")


def contest_entry_insertion():
    """ Inserts the contest entry into the database """
    # establish the connection and create a cursor
    con = sqlite3.connect('baking_contest.db')
    cursor = con.cursor()
    print("Connection re-established")
    # don't quote me on the "bake"ability of the food I list here :)
    cursor.execute("INSERT INTO BakingContestEntry(EntryId, UserID, "
                   "NameOfBakingItem,NumExcellentVotes,NumOkVotes,NumBadVotes) VALUES (1,1,'Chicken Wings',2,2,8)")
    cursor.execute("INSERT INTO BakingContestEntry(EntryId, UserID, "
                   "NameOfBakingItem,NumExcellentVotes,NumOkVotes,NumBadVotes) VALUES (2,2,'Sour Dough Bread',10,2,1)")
    cursor.execute("INSERT INTO BakingContestEntry(EntryId, UserID, "
                   "NameOfBakingItem,NumExcellentVotes,NumOkVotes,NumBadVotes) VALUES (3,3,'Bagel',8,3,1)")
    cursor.execute("INSERT INTO BakingContestEntry(EntryId, UserID, "
                   "NameOfBakingItem,NumExcellentVotes,NumOkVotes,NumBadVotes) VALUES (4,4,'Muffin',7,4,1)")
    cursor.execute("INSERT INTO BakingContestEntry(EntryId, UserID, "
                   "NameOfBakingItem,NumExcellentVotes,NumOkVotes,NumBadVotes) "
                   "VALUES (5,3,'Chocolate Chip Cookie',2,4,5)")
    cursor.execute("INSERT INTO BakingContestEntry(EntryId, UserID, "
                   "NameOfBakingItem,NumExcellentVotes,NumOkVotes,NumBadVotes) "
                   "VALUES (6,3,'Baba Yaga cookie',8,2,2)")
    cursor.execute("INSERT INTO BakingContestEntry(EntryId, UserID, "
                   "NameOfBakingItem,NumExcellentVotes,NumOkVotes,NumBadVotes) "
                   "VALUES (7,1,'KFC Oreo bucket',10,4,5)")

    # select all per instructions
    cursor.execute("SELECT * FROM BakingContestEntry")
    rows: list = cursor.fetchall()

    # print the rows
    print("--BakingContestEntry Table--")
    for row in rows:
        print(row)

    # commit changes close connection
    con.commit()
    con.close()
    print("Connection closed")


# name block
if __name__ == '__main__':
    contest_entry_create()
    contest_entry_insertion()